"""Active validation probe — pure logic + injected transport (no real sockets)."""

from backend.core import active_probe as ap


def test_assess_confirmed_when_version_and_product_in_banner():
    assert ap.assess_probe(True, "nginx/1.18.0", "nginx", "1.18.0") == ap.CONFIRMED_VERSION


def test_assess_present_when_reachable_but_version_absent():
    # Patched without a version bump: service up, banner no longer shows the old version.
    assert ap.assess_probe(True, "nginx", "nginx", "1.18.0") == ap.SERVICE_PRESENT


def test_assess_absent_when_unreachable():
    assert ap.assess_probe(False, "", "nginx", "1.18.0") == ap.ABSENT


def test_assess_requires_product_token_to_confirm():
    # A bare version in an unrelated header must NOT confirm when we know the product.
    assert ap.assess_probe(True, "Apache 1.18.0", "nginx", "1.18.0") == ap.SERVICE_PRESENT


def test_assess_confirms_on_version_alone_when_product_unknown():
    assert ap.assess_probe(True, "something 1.18.0 here", "", "1.18.0") == ap.CONFIRMED_VERSION


def test_verdict_mapping():
    assert ap.probe_to_verdict(ap.CONFIRMED_VERSION)[0] == "confirmed"
    assert ap.probe_to_verdict(ap.ABSENT)[0] == "false_positive"
    assert ap.probe_to_verdict(ap.SERVICE_PRESENT) is None


def test_probe_service_confirmed_with_fake_fetcher():
    fetcher = lambda h, p, t: (True, "nginx/1.18.0")
    verdict, _ = ap.probe_service("h", 80, "nginx", "1.18.0", fetcher=fetcher)
    assert verdict == "confirmed"


def test_probe_service_false_positive_when_unreachable():
    fetcher = lambda h, p, t: (False, "")
    verdict, _ = ap.probe_service("h", 80, "nginx", "1.18.0", fetcher=fetcher)
    assert verdict == "false_positive"


def test_probe_service_defers_when_inconclusive():
    fetcher = lambda h, p, t: (True, "nginx")  # up, version gone
    assert ap.probe_service("h", 80, "nginx", "1.18.0", fetcher=fetcher) is None
