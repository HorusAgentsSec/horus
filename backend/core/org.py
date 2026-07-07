"""Organization helpers — kept dependency-free so the validation is unit-testable."""

MAX_ORG_NAME = 100


class OrgNameError(ValueError):
    """Raised when an organization name fails validation."""


def normalize_org_name(raw: str) -> str:
    """Trims and validates an org name, returning the cleaned value."""
    name = (raw or "").strip()
    if not name:
        raise OrgNameError("Organization name is required.")
    if len(name) > MAX_ORG_NAME:
        raise OrgNameError(f"Organization name must be at most {MAX_ORG_NAME} characters.")
    return name
