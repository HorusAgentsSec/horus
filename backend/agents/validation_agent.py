"""
ValidationAgent — the red/blue adversarial debate that calibrates findings.

This is our adaptation of TradingAgents' bull/bear researcher debate (and CORTEX's "skeptical
reviewer") to a blue team. For each ambiguous finding, the model is made to argue BOTH sides before
ruling: a red-team advocate (why this is real, reachable, exploitable) and a blue-team skeptic (why
it's a false positive, not reachable, or already mitigated). A judge then issues a calibrated
verdict + confidence. Forcing the skeptical case in writing before the verdict is the debiasing
mechanism that kills the version-only and nmap http-* false positives we were shipping at 0.7.

Cost control (this is the only LLM step we add): deterministic triage (core.validation.auto_verdict)
resolves the obvious findings for free — KEV-active is confirmed, info is noise — and only genuinely
ambiguous findings reach the debate, capped per scan. One structured call per debated finding;
verdict, confidence and both arguments are stored on the finding.
"""

import json
import logging

from backend.agents.base import BaseAgent
from backend.agents.state import ScanState
from backend.core import active_probe, validation, verdict_memory
from backend.core.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a two-person validation panel for a blue team, plus a judge.

You receive ONE security finding with its evidence. Produce, in order:
- "red": the strongest case that this is a REAL, reachable, exploitable finding (attacker's view).
- "blue": the strongest case that this is a FALSE POSITIVE — noise, not reachable, already mitigated,
  or a version-only guess. Be genuinely skeptical.
- "verdict": your ruling as judge, one of:
    "confirmed"          — real and actionable, strong evidence.
    "likely"             — probably real, some uncertainty.
    "needs_verification" — cannot decide without an active check.
    "false_positive"     — most likely not a real exposure.
- "confidence": 0.0-1.0, your calibrated confidence that the finding is real.
- "rationale": ONE sentence justifying the verdict.

Ground every claim in the evidence given — do not invent CVEs, versions, or exploits. Treat these as
weak signals unless other evidence supports them: matches made only from a product+version banner,
and nmap scripts that report "potential"/"possible" issues (http-csrf, http-*-xss, http-dombased-xss).

Respond ONLY with a single valid JSON object with exactly those keys."""


class ValidationAgent(BaseAgent):
    agent_type = "validation"

    def run(self, state: ScanState) -> ScanState:
        if not settings.validation_enabled or not state.analyzed_findings:
            return state

        debated = 0
        auto = 0
        probed = 0
        recalled_hits = 0
        cap = settings.validation_max_debates
        enrichment = {e.finding_id: e for e in state.enriched_findings}

        # Index detected services by their "<product> <version>" label (== a finding's
        # source_service) so active validation can find the host:port to probe.
        svc_index = {
            f"{s['product']} {s['version']}": s
            for s in state.detected_services
            if s.get("product") and s.get("version") and s.get("port")
        }

        # Recall how humans judged findings like these — first this org's own feedback (the
        # reflection loop), then the anonymized cross-org community aggregate (the flywheel: a new
        # org benefits from what the whole fleet has learned). One round-trip each; degrade to none.
        signatures = {self._signature(f): f for f in state.analyzed_findings}
        sig_set = set(signatures.keys())
        memory = verdict_memory.recall(state.org_id, sig_set)
        community = verdict_memory.recall_community(sig_set)

        for f in state.analyzed_findings:
            e = enrichment.get(f.id)
            exploitability = e.exploitability if e else None

            # KEV-active is real regardless of any stale memory; it always confirms.
            if (exploitability or "").lower() == "active":
                self._set_verdict(f, "confirmed", f.confidence, rationale=None, debate=None)
                auto += 1
                continue

            sig = self._signature(f)

            # Human prior (this org): a teammate already judged a finding with this signature.
            # Respect it and skip the debate — feedback turning into accuracy (and saved tokens).
            prior = memory.get(sig)
            if prior in ("false_positive", "confirmed"):
                why = (
                    "Matches a finding your team previously marked a false positive"
                    if prior == "false_positive"
                    else "Matches a finding your team previously confirmed as real"
                )
                self._set_verdict(f, prior, None, rationale=why, debate=None)
                recalled_hits += 1
                continue

            # Community prior (anonymized, cross-org): the fleet has a strong consensus on this
            # signature. Apply it so a new org gets clean results immediately. The user can override
            # (their correction becomes an org prior that wins next time).
            cprior = community.get(sig)
            if cprior in ("false_positive", "confirmed"):
                why = (
                    "Commonly a false positive across similar environments (community signal)"
                    if cprior == "false_positive"
                    else "Commonly confirmed as a real exposure across similar environments"
                )
                self._set_verdict(f, cprior, None, rationale=why, debate=None)
                recalled_hits += 1
                continue

            verdict = validation.auto_verdict(f.severity, exploitability, f.confidence)
            if verdict is not None:
                self._set_verdict(f, verdict, f.confidence, rationale=None, debate=None)
                auto += 1
                continue

            # Optional active validation: for a version-only correlation, probe the live service
            # before spending a debate. Confirms (version still exposed) or refutes (service gone)
            # deterministically; inconclusive falls through to the debate. Opt-in (touches network).
            if settings.active_validation_enabled and f.source_service in svc_index:
                probed_verdict = self._active_probe(svc_index[f.source_service], state)
                if probed_verdict is not None:
                    label, why = probed_verdict
                    self._set_verdict(f, label, None, rationale=why, debate=None)
                    probed += 1
                    continue

            # Ambiguous → debate, until the per-scan cap. Past the cap (or in no-cloud mode, where
            # the debate is off), flag for verification deterministically rather than call the LLM.
            if not settings.llm_enabled or debated >= cap:
                reason = ("No-cloud mode: deterministic triage only"
                          if not settings.llm_enabled else "Debate cap reached for this scan")
                self._set_verdict(f, "needs_verification", None, rationale=reason, debate=None)
                continue

            try:
                result = self._debate(f, e, state)
                debated += 1
                self._set_verdict(
                    f,
                    result.get("verdict", "needs_verification"),
                    result.get("confidence"),
                    rationale=result.get("rationale"),
                    debate={"red": result.get("red", ""), "blue": result.get("blue", "")},
                )
            except Exception as exc:
                logger.warning("ValidationAgent: debate failed for %s: %s", f.id, exc)
                self._set_verdict(f, "needs_verification", None,
                                  rationale="Debate unavailable", debate=None)

        fp = sum(1 for f in state.analyzed_findings if f.verdict == "false_positive")
        logger.info(
            "ValidationAgent: %d debated, %d auto-resolved, %d actively probed, %d from memory, "
            "%d flagged false-positive",
            debated, auto, probed, recalled_hits, fp,
        )
        return state

    def _active_probe(self, svc: dict, state: ScanState) -> tuple[str, str] | None:
        """Probe the live service behind a version-only finding. Best-effort: a failed connection
        is itself a signal (false_positive), and any unexpected error defers to the debate."""
        try:
            port = int(svc["port"])
        except (KeyError, ValueError, TypeError):
            return None
        try:
            return active_probe.probe_service(
                state.asset.host, port, svc["product"], svc["version"],
                timeout=settings.active_validation_timeout,
            )
        except Exception as exc:  # never let a probe sink the pipeline
            logger.warning("ValidationAgent: active probe failed for %s:%s: %s",
                           state.asset.host, port, exc)
            return None

    @staticmethod
    def _signature(finding) -> str:
        return verdict_memory.finding_signature(
            source_service=finding.source_service,
            cve_ids=finding.cve_ids,
            title=finding.title,
        )

    @staticmethod
    def _set_verdict(finding, verdict, confidence, rationale, debate) -> None:
        verdict = verdict if verdict in validation.VERDICTS else "needs_verification"
        finding.verdict = verdict
        finding.confidence = validation.confidence_for_verdict(
            verdict, confidence if confidence is not None else finding.confidence
        ) if confidence is None else round(max(0.0, min(1.0, float(confidence))), 2)
        finding.verdict_rationale = rationale
        finding.debate = debate

    def _debate(self, finding, enrichment, state: ScanState) -> dict:
        evidence = {
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "cvss_score": finding.cvss_score,
            "cve_ids": finding.cve_ids,
            "matched_from": finding.source_service,  # set => version-only correlation (weak signal)
            "exploitability": enrichment.exploitability if enrichment else "unknown",
            "threat_context": enrichment.threat_context if enrichment else "",
            "asset_internet_facing": not state.asset.is_internal,
        }
        user_content = json.dumps(evidence, separators=(",", ":"))
        raw, _ = self.call_llm_json(SYSTEM_PROMPT, user_content, max_tokens=512)
        if isinstance(raw, list):
            raw = raw[0] if raw else {}
        return raw if isinstance(raw, dict) else {}
