"""
Model-agnostic agent base using the OpenAI-compatible API.

Supported providers (set via env vars):
  OpenRouter  — LLM_BASE_URL=https://openrouter.ai/api/v1
                LLM_API_KEY=sk-or-...
                LLM_DEFAULT_MODEL=anthropic/claude-opus-4-5

  Ollama      — LLM_BASE_URL=http://localhost:11434/v1
                LLM_API_KEY=ollama   (any non-empty string)
                LLM_DEFAULT_MODEL=llama3.1:70b

  Any OpenAI-compatible endpoint follows the same pattern.
"""

import json
import logging
from abc import ABC, abstractmethod

from openai import OpenAI

from backend.agents.state import ScanState
from backend.core.config import settings

logger = logging.getLogger(__name__)

# Shared client — one instance, all agents use it.
# timeout bounds every request (a hung provider can't stall a pipeline worker
# forever); max_retries handles transient network/5xx errors with backoff.
_client = OpenAI(
    base_url=settings.llm_base_url,
    api_key=settings.llm_api_key or "no-key",  # Ollama ignores the key
    timeout=settings.llm_timeout_seconds,
    max_retries=settings.llm_max_retries,
)


class BaseAgent(ABC):
    agent_type: str = ""
    # Subclasses may override; falls back to settings.llm_default_model
    model: str | None = None

    def __init__(self) -> None:
        self.tokens_used = 0
        self.model_used = None
        # Optional redactor (set per-run by the pipeline). When present and redaction is enabled,
        # prompts are pseudonymized before leaving the process and restored in the response.
        self.redactor = None

    def _resolve_model(self) -> str:
        # Per-agent override from config (e.g. LLM_ANALYST_MODEL)
        per_agent = getattr(settings, f"llm_{self.agent_type}_model", None)
        return per_agent or self.model or settings.llm_default_model

    def call_llm(
        self,
        system: str,
        user_content: str,
        max_tokens: int = 1024,
        json_mode: bool = False,
    ) -> tuple[str, int]:
        """
        Sends a single-turn request to the configured LLM.
        Never passes conversation history — each call is stateless.
        When json_mode is True, asks the provider to constrain output to valid
        JSON (supported by OpenAI, OpenRouter, and Ollama). Falls back silently
        if the provider rejects the parameter.
        Returns (response_text, tokens_used).
        """
        model = self._resolve_model()

        # Privacy: pseudonymize the prompt before it leaves the process. Only user_content carries
        # data (system prompts are static templates). Restored on the response below.
        redactor = self.redactor if (self.redactor and settings.redaction_enabled) else None
        if redactor:
            user_content = redactor.redact(user_content)

        kwargs: dict = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_content},
            ],
        }
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        try:
            response = _client.chat.completions.create(**kwargs)
        except Exception as e:
            # Some providers/models reject response_format with a 400 (bad request).
            # Retry once without it, but only for that case: matching on the exception
            # status code (not a substring of the message) avoids swallowing unrelated
            # failures like timeouts or rate limits.
            if not (json_mode and getattr(e, "status_code", None) == 400):
                raise
            logger.warning(
                "%s: provider rejected response_format (%s); retrying as plain text",
                self.agent_type, e,
            )
            kwargs.pop("response_format", None)
            try:
                response = _client.chat.completions.create(**kwargs)
            except Exception as retry_exc:
                # Preserve the original response_format failure as the cause.
                raise retry_exc from e

        text = response.choices[0].message.content or ""
        if redactor:
            text = redactor.restore(text)  # bring real names back for downstream/persistence
        usage = response.usage
        tokens = (usage.prompt_tokens + usage.completion_tokens) if usage else 0
        self.tokens_used += tokens
        self.model_used = model
        return text, tokens

    def call_llm_json(
        self,
        system: str,
        user_content: str,
        max_tokens: int = 2048,
        retries: int = 2,
    ) -> tuple[dict | list, int]:
        """
        Calls the LLM expecting a JSON response.
        Retries up to `retries` times if parsing fails.
        Returns (parsed_json, total_tokens_used).
        """
        total_tokens = 0
        last_error: Exception | None = None

        for attempt in range(retries + 1):
            retry_note = (
                f"\n\nIMPORTANT: Your previous response was not valid JSON. "
                f"Attempt {attempt + 1}/{retries + 1}. "
                f"Respond ONLY with valid JSON, no markdown fences."
                if attempt > 0
                else ""
            )
            text, tokens = self.call_llm(
                system, user_content + retry_note, max_tokens, json_mode=True
            )
            total_tokens += tokens

            # Strip markdown code fences if present
            cleaned = text.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[-1]
                cleaned = cleaned.rsplit("```", 1)[0].strip()

            try:
                return json.loads(cleaned), total_tokens
            except json.JSONDecodeError as e:
                last_error = e
                logger.warning(
                    f"{self.agent_type} attempt {attempt + 1} JSON parse failed: {e}"
                )

        raise ValueError(
            f"{self.agent_type} failed to produce valid JSON after {retries + 1} attempts: {last_error}"
        )

    @abstractmethod
    def run(self, state: ScanState) -> ScanState:
        pass
