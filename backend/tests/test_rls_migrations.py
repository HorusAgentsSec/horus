"""
Static guard for the project's core invariant: "RLS siempre" (CLAUDE.md) — org isolation is
enforced by Postgres Row Level Security policies, not application code. This can't run RLS
itself (no live Postgres here), but it can catch the regression that actually happens in
practice: a new tenant table (one with an org_id column) added to a migration without the
matching `enable row level security` statement, silently relying on app code to filter by org
instead — exactly the bypass RLS exists to make impossible.
"""

import glob
import re
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "supabase" / "migrations"

_CREATE_TABLE_RE = re.compile(
    r'create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?"?([a-z_][a-z0-9_]*)"?\s*\(',
    re.I,
)
_RLS_ENABLED_RE = re.compile(
    r'alter\s+table\s+(?:public\.)?"?([a-z_][a-z0-9_]*)"?\s+enable\s+row\s+level\s+security',
    re.I,
)


def _tables_with_org_id() -> set[str]:
    tables = set()
    for path in glob.glob(str(MIGRATIONS_DIR / "*.sql")):
        sql = Path(path).read_text(encoding="utf-8")
        for m in _CREATE_TABLE_RE.finditer(sql):
            table = m.group(1).lower()
            # Grab the CREATE TABLE body by counting parens from the opening one, so a
            # later CREATE TABLE in the same file isn't included in this table's column list.
            start = m.end() - 1
            depth, i = 0, start
            while i < len(sql):
                if sql[i] == "(":
                    depth += 1
                elif sql[i] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            body = sql[start:i]
            if re.search(r"\borg_id\b", body, re.I):
                tables.add(table)
    return tables


def _rls_enabled_tables() -> set[str]:
    enabled = set()
    for path in glob.glob(str(MIGRATIONS_DIR / "*.sql")):
        sql = Path(path).read_text(encoding="utf-8")
        enabled.update(m.group(1).lower() for m in _RLS_ENABLED_RE.finditer(sql))
    return enabled


def test_every_org_scoped_table_has_rls_enabled():
    tables_with_org_id = _tables_with_org_id()
    rls_enabled = _rls_enabled_tables()

    assert tables_with_org_id, "sanity check: migration parsing found no org_id tables at all"

    missing = sorted(tables_with_org_id - rls_enabled)
    assert not missing, (
        f"Table(s) {missing} have an org_id column but no "
        f"`enable row level security` statement in supabase/migrations — "
        f"without it, org isolation depends on application code remembering to filter, "
        f"which is exactly what RLS is meant to make unnecessary."
    )
