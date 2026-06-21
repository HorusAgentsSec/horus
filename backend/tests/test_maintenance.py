"""Maintenance (blackout) windows — pure parsing + coverage, no clock."""

from datetime import datetime

from backend.core import maintenance as m


def _dt(day_idx: int, hh: int, mm: int = 0) -> datetime:
    # 2026-06-15 is a Monday (weekday 0); add day_idx for the day we want.
    return datetime(2026, 6, 15 + day_idx, hh, mm)


def test_empty_spec_never_blacks_out():
    assert m.parse_windows("") == []
    assert m.in_blackout(_dt(0, 12), []) is False


def test_business_hours_weekdays():
    w = m.parse_windows("Mon-Fri 09:00-18:00")
    assert m.in_blackout(_dt(0, 12), w) is True       # Monday noon
    assert m.in_blackout(_dt(0, 8, 59), w) is False    # just before
    assert m.in_blackout(_dt(5, 12), w) is False       # Saturday — not in days


def test_day_list_with_commas_is_one_window():
    # The comma inside "Sat,Sun" must not split it into separate windows.
    w = m.parse_windows("Sat,Sun 00:00-23:59")
    assert len(w) == 1
    assert m.in_blackout(_dt(5, 10), w) is True   # Saturday
    assert m.in_blackout(_dt(6, 10), w) is True   # Sunday
    assert m.in_blackout(_dt(0, 10), w) is False  # Monday


def test_no_day_token_means_every_day():
    w = m.parse_windows("22:00-23:00")
    assert m.in_blackout(_dt(2, 22, 30), w) is True
    assert m.in_blackout(_dt(2, 21, 0), w) is False


def test_window_wraps_past_midnight():
    w = m.parse_windows("22:00-02:00")
    assert m.in_blackout(_dt(0, 23), w) is True   # before midnight
    assert m.in_blackout(_dt(0, 1), w) is True    # after midnight
    assert m.in_blackout(_dt(0, 12), w) is False  # midday


def test_multiple_windows_or_together():
    w = m.parse_windows("Mon-Fri 09:00-18:00, Sat,Sun 00:00-23:59")
    assert len(w) == 2
    assert m.in_blackout(_dt(0, 12), w) is True   # weekday window
    assert m.in_blackout(_dt(6, 3), w) is True    # weekend window


def test_malformed_window_is_skipped_not_fatal():
    # "notaday" is junk; the valid window still parses and applies.
    w = m.parse_windows("notaday 09:00-18:00, 22:00-23:00")
    assert m.in_blackout(_dt(0, 22, 30), w) is True
