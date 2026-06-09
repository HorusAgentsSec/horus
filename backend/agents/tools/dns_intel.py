"""DNS security analysis — SPF, DMARC, DKIM, zone transfer."""

import logging
import dns.resolver
import dns.zone
import dns.query
import dns.exception

logger = logging.getLogger(__name__)

_COMMON_DKIM_SELECTORS = (
    "default", "google", "mail", "dkim", "k1", "s1",
    "selector1", "selector2", "smtp", "mandrill",
)


def check_dns_security(domain: str) -> dict:
    """
    Checks email-security and zone-hygiene configuration for a domain.
    Returns a structured dict with findings and a list of human-readable issues.
    """
    results: dict = {
        "domain": domain,
        "spf": None,
        "dmarc": None,
        "dkim_found": False,
        "dkim_selector": None,
        "mx_present": False,
        "zone_transfer_vulnerable": False,
        "ns_servers": [],
        "issues": [],
    }

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    def _query(name: str, rtype: str) -> list[str]:
        try:
            answers = resolver.resolve(name, rtype)
            return [r.to_text() for r in answers]
        except Exception:
            return []

    # ── SPF ──────────────────────────────────────────────────────────────────
    for txt in _query(domain, "TXT"):
        if "v=spf1" in txt:
            results["spf"] = txt
            break
    if not results["spf"]:
        results["issues"].append(
            "No SPF record — the domain can be used to send spoofed emails that pass basic checks"
        )
    elif "+all" in results["spf"]:
        results["issues"].append(
            "SPF uses '+all' — any host is authorized to send as this domain (effectively no protection)"
        )
    elif "~all" in results["spf"]:
        results["issues"].append(
            "SPF uses '~all' (softfail) — spoofed mail is accepted but marked; consider '-all'"
        )

    # ── DMARC ────────────────────────────────────────────────────────────────
    for txt in _query(f"_dmarc.{domain}", "TXT"):
        if "v=DMARC1" in txt:
            results["dmarc"] = txt
            break
    if not results["dmarc"]:
        results["issues"].append(
            "No DMARC record — no policy governs how receivers handle spoofed mail from this domain"
        )
    elif "p=none" in results["dmarc"]:
        results["issues"].append(
            "DMARC policy is 'p=none' (monitor-only) — spoofed mail is delivered, not rejected"
        )

    # ── DKIM ─────────────────────────────────────────────────────────────────
    for sel in _COMMON_DKIM_SELECTORS:
        for txt in _query(f"{sel}._domainkey.{domain}", "TXT"):
            if "v=DKIM1" in txt:
                results["dkim_found"] = True
                results["dkim_selector"] = sel
                break
        if results["dkim_found"]:
            break
    if not results["dkim_found"]:
        results["issues"].append(
            "No DKIM record found for common selectors — emails from this domain lack cryptographic signing"
        )

    # ── MX ───────────────────────────────────────────────────────────────────
    results["mx_present"] = bool(_query(domain, "MX"))

    # ── Zone transfer ────────────────────────────────────────────────────────
    ns_records = _query(domain, "NS")
    results["ns_servers"] = [r.rstrip(".") for r in ns_records]
    for ns in results["ns_servers"][:3]:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5, lifetime=8))
            if zone:
                results["zone_transfer_vulnerable"] = True
                results["issues"].append(
                    f"Zone transfer allowed from {ns} — exposes the full DNS record set to any requester"
                )
                break
        except (dns.exception.FormError, EOFError, TimeoutError, ConnectionRefusedError):
            pass
        except Exception:
            pass

    return results
