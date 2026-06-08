import asyncio

from backend.api.assets import create_asset, update_asset
from backend.models.schemas import AssetCreate, AssetUpdate


USER = {"id": "user-1", "org_id": "org-1", "role": "analyst"}


class Result:
    def __init__(self, data):
        self.data = data


class FakeQuery:
    def __init__(self, rows, table_name):
        self.rows = rows
        self.table_name = table_name
        self.inserted = None
        self.updates = None
        self.filters = {}

    def select(self, _columns):
        return self

    def insert(self, payload):
        self.inserted = payload
        return self

    def update(self, payload):
        self.updates = payload
        return self

    def eq(self, column, value):
        self.filters[column] = value
        return self

    def execute(self):
        if self.inserted is not None:
            row = {"id": "asset-new", **self.inserted}
            self.rows.append(row)
            return Result([row])

        if self.updates is not None:
            row = self._matching_row()
            row.update(self.updates)
            return Result([row])

        row = self._matching_row()
        return Result([row] if row else [])

    def _matching_row(self):
        for row in self.rows:
            if all(row.get(column) == value for column, value in self.filters.items()):
                return row
        return None


class FakeDb:
    def __init__(self, rows=None):
        self.rows = rows or []

    def table(self, table_name):
        assert table_name == "assets"
        return FakeQuery(self.rows, table_name)


def test_create_asset_writes_audit_entry(monkeypatch):
    audit_calls = []
    monkeypatch.setattr("backend.api.assets.log_action", lambda *args, **kwargs: audit_calls.append((args, kwargs)))
    db = FakeDb()

    result = asyncio.run(create_asset(
        AssetCreate(name="App", host="example.com", type="web", tags=["prod"]),
        user=USER,
        db=db,
    ))

    assert result["id"] == "asset-new"
    assert audit_calls == [(
        ("org-1", "user-1", "asset.created"),
        {
            "entity_type": "asset",
            "entity_id": "asset-new",
            "metadata": {
                "name": "App",
                "host": "example.com",
                "type": "web",
                "is_internal": False,
            },
        },
    )]


def test_update_asset_writes_changed_fields_to_audit(monkeypatch):
    audit_calls = []
    monkeypatch.setattr("backend.api.assets.log_action", lambda *args, **kwargs: audit_calls.append((args, kwargs)))
    db = FakeDb([{
        "id": "asset-1",
        "org_id": "org-1",
        "name": "Old",
        "host": "example.com",
        "is_internal": False,
    }])

    result = asyncio.run(update_asset(
        "asset-1",
        AssetUpdate(name="New", tags=["critical"]),
        user=USER,
        db=db,
    ))

    assert result["name"] == "New"
    assert audit_calls[0][0] == ("org-1", "user-1", "asset.updated")
    assert audit_calls[0][1]["entity_id"] == "asset-1"
    assert audit_calls[0][1]["metadata"]["changed_fields"] == ["name", "tags"]


def test_update_host_uses_existing_internal_scope(monkeypatch):
    monkeypatch.setattr("backend.api.assets.log_action", lambda *args, **kwargs: None)
    db = FakeDb([{
        "id": "asset-1",
        "org_id": "org-1",
        "name": "Internal API",
        "host": "10.0.0.5",
        "is_internal": True,
    }])

    result = asyncio.run(update_asset(
        "asset-1",
        AssetUpdate(host="10.0.0.6"),
        user=USER,
        db=db,
    ))

    assert result["host"] == "10.0.0.6"
