"""Tests for the password strength policy used by the forced-change flow."""

import pytest

from backend.core.password import (
    MIN_LENGTH,
    PasswordPolicyError,
    validate_password_strength,
)


def test_accepts_strong_password():
    validate_password_strength("Str0ngPassw0rd!")  # no exception


def test_rejects_too_short():
    with pytest.raises(PasswordPolicyError, match="at least"):
        validate_password_strength("Ab1" + "x" * (MIN_LENGTH - 4))


def test_rejects_missing_lowercase():
    with pytest.raises(PasswordPolicyError, match="lowercase"):
        validate_password_strength("ABCDEFGH1234")


def test_rejects_missing_uppercase():
    with pytest.raises(PasswordPolicyError, match="uppercase"):
        validate_password_strength("abcdefgh1234")


def test_rejects_missing_digit():
    with pytest.raises(PasswordPolicyError, match="digit"):
        validate_password_strength("abcdEFGHijkl")


def test_minimum_length_boundary():
    # Exactly MIN_LENGTH with all classes present is accepted.
    pw = "Aa1" + "b" * (MIN_LENGTH - 3)
    assert len(pw) == MIN_LENGTH
    validate_password_strength(pw)
