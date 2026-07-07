"""
Redaction — pseudonymize sensitive identifiers before they reach a cloud LLM.

A security platform shouldn't hand an external model your infrastructure map. The deterministic core
(CVE correlation, SSVC, posture) already never calls an LLM; this covers the agents that do (analyst,
validation debate, remediation, reporter). Before a prompt leaves the process we swap the crown
jewels — asset hostnames/names, IPs, emails, and other FQDNs — for stable placeholders ([HOST_1],
[IP_1], …), then restore them in the model's response so persisted findings still read naturally. The
model reasons over structure (products, versions, severities, CVEs) which is preserved; it never sees
the literal names.

Honest limitations: this is pseudonymization, not encryption — it shrinks the blast radius, it
doesn't eliminate trust in the provider (for that, see the no-cloud and TEE tiers). And it's
best-effort: an identifier we don't seed and can't pattern-match could slip through. Reference
domains (nvd.nist.gov, mitre.org…) are deliberately NOT redacted so CVE links keep working.

`Redactor` is pure and unit-tested; `build_redactor` seeds one from a ScanState.
"""

import re

# Unambiguous patterns that are safe to auto-redact wherever they appear.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# A hostname/FQDN: one or more dot-separated labels ending in an alpha TLD.
_FQDN = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")

# Public reference domains we keep in the clear — they carry no customer info and the model (and the
# restored output) benefits from real CVE/advisory links.
_ALLOW_DOMAINS = (
    "nvd.nist.gov", "cisa.gov", "mitre.org", "first.org", "cve.org", "github.com",
    "nginx.org", "apache.org", "openssl.org", "kb.cert.org", "exploit-db.com",
)

# Don't redact a seed shorter than this — short/common asset names ("web", "db") would clobber
# unrelated words. IPs/emails/FQDNs are matched structurally, so this only guards explicit seeds.
_MIN_SEED_LEN = 4


def _is_allowed(host: str) -> bool:
    h = host.lower()
    return any(h == d or h.endswith("." + d) for d in _ALLOW_DOMAINS)


class Redactor:
    """Bidirectional, stable map between sensitive values and placeholders. Same value → same
    placeholder within one instance, so the model sees a coherent (if anonymized) world."""

    def __init__(self, seeds: list[tuple[str, str]] | None = None):
        self._map: dict[str, str] = {}      # real value -> placeholder
        self._rev: dict[str, str] = {}      # placeholder -> real value
        self._counts: dict[str, int] = {}
        # Explicit seeds: (value, kind). Longer values first so a host isn't partially masked.
        for value, kind in sorted(seeds or [], key=lambda s: len(s[0]), reverse=True):
            if value and len(value) >= _MIN_SEED_LEN:
                self._placeholder_for(value, kind)

    def _placeholder_for(self, value: str, kind: str) -> str:
        if value in self._map:
            return self._map[value]
        n = self._counts.get(kind, 0) + 1
        self._counts[kind] = n
        ph = f"[{kind}_{n}]"
        self._map[value] = ph
        self._rev[ph] = value
        return ph

    def redact(self, text: str) -> str:
        if not text:
            return text
        # 1) Explicit seeds first, longest-first, on word boundaries.
        for real in sorted(self._map, key=len, reverse=True):
            text = re.sub(rf"\b{re.escape(real)}\b", self._map[real], text)
        # 2) Structural auto-detection: emails, then IPs, then other FQDNs.
        text = _EMAIL.sub(lambda m: self._placeholder_for(m.group(0), "EMAIL"), text)
        text = _IP.sub(lambda m: self._placeholder_for(m.group(0), "IP"), text)
        text = _FQDN.sub(
            lambda m: m.group(0) if _is_allowed(m.group(0)) else self._placeholder_for(m.group(0), "HOST"),
            text,
        )
        return text

    def restore(self, text: str) -> str:
        if not text:
            return text
        for ph, real in self._rev.items():
            text = text.replace(ph, real)
        return text

    @property
    def active(self) -> bool:
        return bool(self._map)


def build_redactor(state) -> Redactor:
    """Seed a redactor from a ScanState's known-sensitive values (asset host + name)."""
    seeds: list[tuple[str, str]] = []
    asset = getattr(state, "asset", None)
    if asset:
        if getattr(asset, "host", None):
            seeds.append((asset.host, "HOST"))
        if getattr(asset, "name", None):
            seeds.append((asset.name, "NAME"))
    return Redactor(seeds)
