"""
Passive asset discovery by domain.

Maps a domain's attack surface WITHOUT scanning: subdomains come from Certificate
Transparency logs (crt.sh), and DNS resolution filters out dead names. Hosts that
resolve to public IPs are auto-created as assets so the rest of the pipeline can scan
them later. Anything that resolves to a private/reserved/metadata range is rejected by
the same guard the scanners use (target_validation) — we never silently add internal
infrastructure discovered from public logs.

This is the "give me a domain, I'll find and watch everything" capability.
"""

import ipaddress
import logging
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import dns.resolver
import httpx

from backend.core.audit import log_action
from backend.core.config import settings
from backend.core.supabase_client import supabase  # service-role: bypasses RLS
from backend.core.target_validation import validate_scan_target, TargetValidationError

logger = logging.getLogger(__name__)


def _keep(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def _fetch_crtsh(domain: str) -> set[str]:
    """Subdomains from crt.sh. Retries (it's slow/flaky and sometimes 200s with junk)."""
    last_err: Exception | None = None
    rows = None
    for attempt in range(settings.discovery_crtsh_retries + 1):
        try:
            resp = httpx.get(
                settings.discovery_crtsh_url,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=settings.discovery_timeout_seconds,
                follow_redirects=True,
            )
            resp.raise_for_status()
            rows = resp.json()
            break
        except (httpx.TransportError, httpx.HTTPStatusError, ValueError) as e:
            last_err = e
            logger.warning("discovery: crt.sh attempt %d failed for %s: %s", attempt + 1, domain, e)
    if rows is None:
        raise RuntimeError(f"crt.sh unavailable: {last_err}")
    names: set[str] = set()
    for row in rows:
        for raw in (row.get("name_value", "") or "").split("\n"):
            name = raw.strip().lstrip("*.").lower()
            if _keep(name, domain):
                names.add(name)
    return names


def _fetch_certspotter(domain: str) -> set[str]:
    """Subdomains from certspotter — fallback CT source when crt.sh is down."""
    resp = httpx.get(
        settings.discovery_certspotter_url,
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
        timeout=settings.discovery_timeout_seconds,
        follow_redirects=True,
    )
    resp.raise_for_status()
    names: set[str] = set()
    for entry in resp.json():
        for raw in entry.get("dns_names", []):
            name = raw.strip().lstrip("*.").lower()
            if _keep(name, domain):
                names.add(name)
    return names


def discover_subdomains(domain: str) -> set[str]:
    """
    Subdomains of `domain` from Certificate Transparency logs. Passive. Uses crt.sh,
    falling back to certspotter when crt.sh is unavailable (it frequently is).
    """
    domain = domain.strip().lower().lstrip(".")
    try:
        names = _fetch_crtsh(domain)
        source = "crt.sh"
    except Exception as e:
        logger.warning("discovery: crt.sh failed for %s (%s); trying certspotter", domain, e)
        names = _fetch_certspotter(domain)
        source = "certspotter"
    logger.info("discovery: %s returned %d unique names for %s", source, len(names), domain)
    return names


def resolve_ips(host: str) -> list[str]:
    """A/AAAA records for `host`, or [] if it doesn't resolve."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver.timeout = 5.0
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            ips.extend(r.to_text() for r in resolver.resolve(host, rtype))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
                dns.resolver.LifetimeTimeout):
            continue
    return ips


def run_discovery(source_id: str, org_id: str) -> dict:
    """Loads a source and runs the right discovery pass (domain or private network)."""
    source = (
        supabase.table("discovery_sources").select("*").eq("id", source_id).single().execute().data
    )
    if source.get("kind") == "network":
        return _run_network(source, org_id)
    return _run_domain(source, org_id)


def _run_domain(source: dict, org_id: str) -> dict:
    """
    Passive domain discovery: enumerate (CT logs) -> resolve -> validate -> create assets.
    Updates the source's last_run_at / last_found_count.
    """
    domain = source["domain"]
    auto_create = source.get("auto_create_assets", True)

    names = discover_subdomains(domain)

    # Existing hosts in this org — dedupe so we never create duplicates.
    existing = {
        a["host"]
        for a in supabase.table("assets").select("host").eq("org_id", org_id).execute().data
    }

    found_live = 0
    created = 0
    skipped_dead = skipped_unsafe = skipped_existing = 0

    for host in sorted(names):
        if settings.discovery_resolve_dns and not resolve_ips(host):
            skipped_dead += 1
            continue
        found_live += 1

        try:
            validate_scan_target(host, is_internal=False)
        except TargetValidationError:
            skipped_unsafe += 1  # resolves to private/reserved/metadata — don't add
            continue

        if host in existing:
            skipped_existing += 1
            continue

        if auto_create and created < settings.discovery_max_assets_per_run:
            supabase.table("assets").insert({
                "org_id": org_id,
                "name": host,
                "host": host,
                "type": "domain",
                "is_internal": False,
                "tags": ["discovered"],
            }).execute()
            existing.add(host)
            created += 1

    supabase.table("discovery_sources").update({
        "last_run_at": datetime.now(timezone.utc).isoformat(),
        "last_found_count": found_live,
    }).eq("id", source["id"]).execute()

    log_action(
        org_id, source["id"], "discovery.run",
        actor_type="system", entity_type="discovery_source", entity_id=source["id"],
        metadata={"domain": domain, "found": found_live, "created": created},
    )

    summary = {
        "domain": domain,
        "names": len(names),
        "found_live": found_live,
        "created": created,
        "skipped_existing": skipped_existing,
        "skipped_dead": skipped_dead,
        "skipped_unsafe": skipped_unsafe,
    }
    logger.info("discovery complete: %s", summary)
    return summary


# ── Private-network discovery (active ping sweep) ────────────────────────────

def _validate_private_cidr(cidr: str) -> ipaddress._BaseNetwork:
    """
    Parse a CIDR and refuse anything that isn't a private (RFC1918-style) range or is
    too large. This is the abuse guard: we never sweep public ranges (that's scanning
    infrastructure you may not own) and never a /8-sized blast radius by accident.
    """
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR '{cidr}': {e}")
    if not network.is_private:
        raise ValueError(f"{cidr} is not a private range — network discovery only sweeps private CIDRs")
    if network.num_addresses > settings.discovery_network_max_hosts:
        raise ValueError(
            f"{cidr} has {network.num_addresses} addresses; max is "
            f"{settings.discovery_network_max_hosts} (use a smaller CIDR)"
        )
    return network


def _parse_sweep_xml(stdout: str) -> list[dict]:
    """Parse nmap -sn XML output into [{ip, hostname}] for the hosts that are up."""
    hosts: list[dict] = []
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError:
        logger.warning("discovery: could not parse nmap sweep output")
        return hosts
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = ""
        for addr in host_el.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip = addr.get("addr", "")
        if not ip:
            continue
        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None
        hosts.append({"ip": ip, "hostname": hostname})
    return hosts


def discover_hosts(cidr: str) -> list[dict]:
    """Live hosts in a private CIDR via an nmap ping sweep. Returns [{ip, hostname}]."""
    _validate_private_cidr(cidr)  # never shell out to nmap on an unvalidated/public range
    cmd = ["nmap", "-sn", "-T4", "--max-retries", "1", "-oX", "-", cidr]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=settings.discovery_nmap_sweep_timeout
    )
    hosts = _parse_sweep_xml(proc.stdout)
    logger.info("discovery: nmap sweep of %s found %d live hosts", cidr, len(hosts))
    return hosts


def _run_network(source: dict, org_id: str) -> dict:
    """Active sweep of a private CIDR -> create internal assets (is_internal=true)."""
    cidr = source.get("network_cidr") or ""
    auto_create = source.get("auto_create_assets", True)
    _validate_private_cidr(cidr)  # raises on public/oversized; surfaces as a failed run

    live = discover_hosts(cidr)

    existing = {
        a["host"]
        for a in supabase.table("assets").select("host").eq("org_id", org_id).execute().data
    }
    created = skipped_existing = 0
    for host in live:
        ip = host["ip"]
        if ip in existing:
            skipped_existing += 1
            continue
        if auto_create and created < settings.discovery_max_assets_per_run:
            supabase.table("assets").insert({
                "org_id": org_id,
                "name": host.get("hostname") or ip,
                "host": ip,
                "type": "ip",
                "is_internal": True,  # discovered inside a private range
                "tags": ["discovered", "internal"],
            }).execute()
            existing.add(ip)
            created += 1

    supabase.table("discovery_sources").update({
        "last_run_at": datetime.now(timezone.utc).isoformat(),
        "last_found_count": len(live),
    }).eq("id", source["id"]).execute()

    log_action(
        org_id, source["id"], "discovery.run",
        actor_type="system", entity_type="discovery_source", entity_id=source["id"],
        metadata={"cidr": cidr, "found": len(live), "created": created},
    )

    summary = {
        "cidr": cidr,
        "found_live": len(live),
        "created": created,
        "skipped_existing": skipped_existing,
    }
    logger.info("network discovery complete: %s", summary)
    return summary
