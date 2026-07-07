from backend.api.scans import _with_triggered_by_labels


class Result:
    def __init__(self, data):
        self.data = data


class FakeProfilesQuery:
    def __init__(self, profiles):
        self.profiles = profiles
        self.ids = []

    def select(self, _columns):
        return self

    def in_(self, _column, values):
        self.ids = values
        return self

    def execute(self):
        return Result([p for p in self.profiles if p["id"] in self.ids])


class FakeDb:
    def __init__(self, profiles):
        self.profiles = profiles

    def table(self, table_name):
        assert table_name == "profiles"
        return FakeProfilesQuery(self.profiles)


def test_scan_triggered_by_uses_profile_name_when_available():
    scans = [{"triggered_by": "user:user-1", "triggered_by_user_id": "user-1"}]
    result = _with_triggered_by_labels(
        scans,
        FakeDb([{"id": "user-1", "full_name": "Ada Lovelace"}]),
        {"id": "user-1", "email": "ada@example.com"},
    )

    assert result[0]["triggered_by_label"] == "Ada Lovelace"


def test_scan_triggered_by_falls_back_to_current_user_email():
    scans = [{"triggered_by": "user:user-1"}]
    result = _with_triggered_by_labels(
        scans,
        FakeDb([{"id": "user-1", "full_name": None}]),
        {"id": "user-1", "email": "ada@example.com"},
    )

    assert result[0]["triggered_by_label"] == "ada@example.com"


def test_scan_triggered_by_shows_schedule_label():
    scans = [{"triggered_by": "schedule"}]
    result = _with_triggered_by_labels(scans, FakeDb([]), {"id": "user-1"})

    assert result[0]["triggered_by_label"] == "Schedule"
