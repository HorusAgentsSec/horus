from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class AssetInfo(BaseModel):
    id: str
    name: str
    host: str
    port: Optional[int] = None
    type: str
    is_internal: bool
    tags: list[str]


class RawFinding(BaseModel):
    tool: str  # nuclei / nmap / zap
    template_id: Optional[str] = None
    name: str
    host: str
    severity: str
    raw: dict


class AnalyzedFinding(BaseModel):
    id: str  # deterministic fingerprint
    title: str
    description: str
    severity: str  # critical/high/medium/low/info
    cvss_score: Optional[float] = None
    cve_ids: list[str] = []
    confidence: float  # 0-1, confidence this is real (calibrated by the ValidationAgent debate)
    rationale: str
    # Set by the CorrelationAgent: "<product> <version>" the CVE was matched from,
    # so the UI can group many CVEs of one service into a single row.
    source_service: Optional[str] = None
    # Set by the ValidationAgent (red/blue debate): confirmed | likely | needs_verification |
    # false_positive. None until validated. `debate` holds the two advocates' arguments.
    verdict: Optional[str] = None
    verdict_rationale: Optional[str] = None
    debate: Optional[dict] = None


class EnrichedFinding(BaseModel):
    finding_id: str
    threat_context: str
    exploitability: str  # none/low/medium/high/active
    public_exploits_exist: bool
    references: list[str] = []


class RemediationSuggestion(BaseModel):
    finding_id: str
    action_type: str
    title: str
    description: str
    command_or_patch: Optional[str] = None
    estimated_risk: str  # low/medium/high — risk of the fix itself
    confidence: float


class RiskDecision(BaseModel):
    suggestion_id: str
    mode: str  # auto / approval_required / suggest_only (after the safety clamp)
    reason: str
    # SSVC deployer assessment (priority label + decision points), when no explicit permission
    # rule matched. None when a rule decided the mode. Surfaced in the UI for "why this urgency".
    ssvc: Optional[dict] = None
    # Remediation safety tier (reversible/disruptive/destructive) — the hard ceiling on autonomy.
    safety_tier: Optional[str] = None


class ScanReport(BaseModel):
    summary: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    top_priorities: list[str]  # finding IDs ordered by priority
    recommended_next_steps: str


class ScanState(BaseModel):
    scan_id: str
    org_id: str
    asset: AssetInfo
    permission_rules: list[dict] = []
    raw_findings: list[RawFinding] = []
    # Services detected by version scanning (product/version per open port), used for
    # CPE->CVE correlation against NVD. Distinct from raw_findings (which are vuln hits).
    detected_services: list[dict] = []
    analyzed_findings: list[AnalyzedFinding] = []
    enriched_findings: list[EnrichedFinding] = []
    remediation_suggestions: list[RemediationSuggestion] = []
    risk_decisions: list[RiskDecision] = []
    report: Optional[ScanReport] = None
    errors: list[str] = []
    canceled: bool = False
