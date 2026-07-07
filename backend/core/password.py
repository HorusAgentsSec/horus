"""
Password strength policy — shared rule for user-chosen passwords.

Kept dependency-free so it is unit-testable in isolation. Mirrors the complexity of
the generated temp passwords (upper/lower/digit) with a sane minimum length.
"""

import secrets
import string

MIN_LENGTH = 12


def generate_temp_password(length: int = 16) -> str:
    """Cryptographically random password guaranteed to satisfy validate_password_strength
    (lower + upper + digit). Used for provisioned/invited accounts that must change it."""
    body_len = max(length - 3, MIN_LENGTH - 3)
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(body_len))
    # Guarantee one of each required class regardless of what the random body produced.
    return (
        body
        + secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.digits)
    )


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


if __name__ == "__main__":
    # Self-check: every generated temp password must satisfy the policy.
    for _ in range(1000):
        validate_password_strength(generate_temp_password())
    print("ok: generate_temp_password always passes validate_password_strength")
