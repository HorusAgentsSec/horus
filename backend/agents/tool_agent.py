"""
ToolAgent — BaseAgent extended with a proper OpenAI tool-calling loop.

The loop:
  1. Send messages + tools to the LLM.
  2. If the model returns tool_calls, execute each via the provided executor dict.
  3. Append the assistant message and tool results to the conversation.
  4. Repeat until finish_reason == "stop" (or max_iterations).

This is the difference between a pipeline step (one LLM call, fixed output) and
an agent (the model decides which tools to call, in what order, and when to stop).
"""

import json
import logging
from typing import Any, Callable, Optional

from backend.agents.base import BaseAgent, _client
from backend.agents.state import ScanState

logger = logging.getLogger(__name__)


class ToolAgent(BaseAgent):
    """Abstract base for agents that use tool-calling loops."""

    def run_with_tools(
        self,
        system: str,
        user_content: str,
        tools: list[dict],
        executor: dict[str, Callable[..., Any]],
        max_iterations: int = 20,
        emit: Optional[Callable[[dict], None]] = None,
        job_id: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> tuple[str, int]:
        """
        Runs the tool-calling loop.

        Args:
            tools:     OpenAI-format tool definitions (list of {"type":"function", ...}).
            executor:  Mapping from tool name to the Python callable that implements it.
            max_iterations: Safety ceiling — avoids infinite loops on misbehaving models.

        Returns:
            (final_text, total_tokens_used)
        """
        model = self._resolve_model()
        messages: list[dict] = [
            {"role": "system", "content": system},
            {"role": "user",   "content": user_content},
        ]
        total_tokens = 0

        for iteration in range(max_iterations):
            from backend.core import cancel as _cancel
            if _cancel.is_canceled(job_id):
                logger.info("%s: job canceled, stopping at iteration %d", self.agent_type, iteration)
                self.tokens_used += total_tokens
                return "", total_tokens

            # Honor the org token budget between iterations: a model that keeps calling
            # tools can otherwise burn through the limit across up to max_iterations calls.
            if org_id is not None:
                from backend.core.token_budget import check_budget
                if not check_budget(org_id)["ok"]:
                    logger.warning(
                        "%s: token budget exceeded, stopping at iteration %d", self.agent_type, iteration
                    )
                    self.tokens_used += total_tokens
                    return "", total_tokens

            try:
                response = _client.chat.completions.create(
                    model=model,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                )
            except Exception as e:
                # Some providers don't support tool_choice="auto" — retry without it
                if "tool_choice" in str(e):
                    response = _client.chat.completions.create(
                        model=model,
                        messages=messages,
                        tools=tools,
                    )
                else:
                    raise

            usage = response.usage
            if usage:
                total_tokens += usage.prompt_tokens + usage.completion_tokens
            self.model_used = model

            choice = response.choices[0]
            msg = choice.message
            is_final = choice.finish_reason == "stop" or not msg.tool_calls

            if emit and msg.content and msg.content.strip():
                emit({
                    "type": "model_thought",
                    "agent": self.agent_type,
                    "text": msg.content.strip(),
                    "final": is_final,
                })

            # Add the raw assistant message object to history
            messages.append(msg)

            if is_final:
                final_text = msg.content or ""
                self.tokens_used += total_tokens
                return final_text, total_tokens

            # Execute each requested tool call
            for tc in msg.tool_calls:
                tool_name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}

                fn = executor.get(tool_name)
                if fn is None:
                    tool_result = {"error": f"Unknown tool: {tool_name}"}
                else:
                    if emit:
                        subject = next(
                            (str(v)[:80] for v in args.values() if isinstance(v, str)), ""
                        )
                        emit({"type": "tool_call", "agent": self.agent_type, "tool": tool_name, "subject": subject})
                    try:
                        logger.debug(
                            "%s → calling tool %s(%s)",
                            self.agent_type, tool_name,
                            ", ".join(f"{k}={v!r}" for k, v in args.items()),
                        )
                        tool_result = fn(**args)
                    except Exception as e:
                        logger.warning("%s tool %s failed: %s", self.agent_type, tool_name, e)
                        tool_result = {"error": str(e)}
                    if emit:
                        ok = not (isinstance(tool_result, dict) and "error" in tool_result)
                        emit({"type": "tool_result", "agent": self.agent_type, "tool": tool_name, "ok": ok})

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(tool_result, default=str),
                })

            logger.debug("%s completed iteration %d/%d", self.agent_type, iteration + 1, max_iterations)

        # Fell through max iterations — return whatever the last assistant message said
        last_assistant = next(
            (m for m in reversed(messages)
             if (getattr(m, "role", None) or (m.get("role") if isinstance(m, dict) else None)) == "assistant"),
            None,
        )
        final_text = ""
        if last_assistant:
            final_text = (
                getattr(last_assistant, "content", None)
                or (last_assistant.get("content") if isinstance(last_assistant, dict) else "")
                or ""
            )
        self.tokens_used += total_tokens
        logger.warning("%s hit max_iterations=%d", self.agent_type, max_iterations)
        return final_text, total_tokens
