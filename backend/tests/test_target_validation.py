"""Security tests for scan-target validation. These guard against SSRF and
scanner argument-injection — regressions here are security incidents."""

import pytest
from backend.core.target_validation import validate_scan_target, TargetValidationError


@pytest.mark.parametrize("host", [
    "169.254.169.254",          # AWS/GCP/Azure metadata
    "100.100.100.200",          # Alibaba metadata
    "-oX /etc/passwd",          # nmap argument injection
    "-target",                  # flag injection
    "a; rm -rf /",              # shell metacharacters
    "host`whoami`",             # command substitution chars
    "",                         # empty
])
def test_blocks_unsafe_targets(host):
    with pytest.raises(TargetValidationError):
        validate_scan_target(host, is_internal=False)


@pytest.mark.parametrize("host", [
    "10.0.0.5", "192.168.1.1", "127.0.0.1", "localhost",
])
def test_blocks_private_as_external(host):
    with pytest.raises(TargetValidationError):
        validate_scan_target(host, is_internal=False)


@pytest.mark.parametrize("host", ["10.0.0.5", "192.168.1.1"])
def test_allows_private_when_internal(host):
    assert validate_scan_target(host, is_internal=True) == host


def test_metadata_blocked_even_when_internal():
    # Cloud metadata is never legitimate, internal flag must not bypass it
    with pytest.raises(TargetValidationError):
        validate_scan_target("169.254.169.254", is_internal=True)


@pytest.mark.parametrize("host,expected", [
    ("example.com", "example.com"),
    ("scanme.nmap.org:443", "scanme.nmap.org"),
    ("https://scanme.nmap.org/path", "scanme.nmap.org"),
])
def test_allows_legitimate_targets(host, expected):
    assert validate_scan_target(host, is_internal=False) == expected
