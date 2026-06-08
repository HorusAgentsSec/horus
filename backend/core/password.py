"""
Password strength policy — shared rule for user-chosen passwords.

Kept dependency-free so it is unit-testable in isolation. Mirrors the complexity of
the generated temp passwords (upper/lower/digit) with a sane minimum length.
"""

MIN_LENGTH = 12


class PasswordPolicyError(ValueError):
    """Raised when a password fails the strength policy."""


def validate_password_strength(password: str) -> None:
    """Raises PasswordPolicyError describing the first rule the password violates."""
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(f"Password must be at least {MIN_LENGTH} characters long.")
    if not any(c.islower() for c in password):
        raise PasswordPolicyError("Password must contain a lowercase letter.")
    if not any(c.isupper() for c in password):
        raise PasswordPolicyError("Password must contain an uppercase letter.")
    if not any(c.isdigit() for c in password):
        raise PasswordPolicyError("Password must contain a digit.")
