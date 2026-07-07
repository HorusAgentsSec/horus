"""Tests for DNS brute-force subdomain discovery (added 2026-06-20)."""

from backend.core import discovery


def test_bruteforce_keeps_only_resolving_names(monkeypatch):
    # Only "www" and "api" "resolve"; everything else returns no IPs and is dropped.
    live = {"www.example.com": ["1.2.3.4"], "api.example.com": ["1.2.3.5"]}
    monkeypatch.setattr(discovery, "resolve_ips", lambda host: live.get(host, []))

    found = discovery._bruteforce_subdomains("example.com")

    assert found == {"www.example.com", "api.example.com"}


def test_discover_subdomains_unions_ct_and_bruteforce(monkeypatch):
    monkeypatch.setattr(discovery.settings, "discovery_dns_bruteforce", True)
    monkeypatch.setattr(discovery, "_fetch_crtsh", lambda d: {"ct.example.com"})
    monkeypatch.setattr(discovery, "_bruteforce_subdomains", lambda d: {"www.example.com"})

    names = discovery.discover_subdomains("example.com")

    assert names == {"ct.example.com", "www.example.com"}


def test_bruteforce_can_be_disabled(monkeypatch):
    monkeypatch.setattr(discovery.settings, "discovery_dns_bruteforce", False)
    monkeypatch.setattr(discovery, "_fetch_crtsh", lambda d: {"ct.example.com"})
    # If brute-force ran it would raise — proving it's skipped when disabled.
    monkeypatch.setattr(
        discovery, "_bruteforce_subdomains",
        lambda d: (_ for _ in ()).throw(AssertionError("brute-force should be skipped")),
    )

    names = discovery.discover_subdomains("example.com")

    assert names == {"ct.example.com"}
