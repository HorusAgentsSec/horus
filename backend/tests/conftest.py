"""
Shared pytest configuration for the backend test suite.

The Supabase client validates its URL and API key (JWT format) at instantiation
time, which causes import failures when running tests without real credentials.
We stub the module-level `supabase` singleton before any test module is collected
so tests can import any backend module that depends on it without crashing.
"""

import sys
from unittest.mock import MagicMock

# Stub the supabase_client module before any backend module is imported.
# This must run at conftest load time (before test collection) so that
# `from backend.core.supabase_client import supabase` in any module returns
# the mock rather than attempting to connect to a real Supabase instance.
_mock_supabase = MagicMock()

_mock_supabase_client_module = MagicMock()
_mock_supabase_client_module.supabase = _mock_supabase

sys.modules.setdefault("backend.core.supabase_client", _mock_supabase_client_module)
