import httpx

from supabase import create_client, Client
from backend.core.config import settings


def _force_http1(client: Client) -> Client:
    """
    postgrest 0.17 hardcodes ``http2=True`` on its httpx session. A sync httpx client
    over HTTP/2 multiplexes every request onto a single TCP connection, and driving that
    connection from several worker threads at once (concurrent scans + discovery sharing
    the global service-role client) corrupts the HTTP/2 state machine — the server then
    drops the connection and postgrest surfaces ``RemoteProtocolError: Server disconnected``.
    Rebuild the session over HTTP/1.1, whose pooled connections are thread-safe.
    """
    old = client.postgrest.session
    client.postgrest.session = httpx.Client(
        base_url=old.base_url,
        headers=old.headers,
        timeout=old.timeout,
        follow_redirects=True,
        http2=False,
    )
    old.close()
    return client


# Service-role client — bypasses RLS. Use ONLY for backend/admin operations:
# the agent pipeline persistence, auth.admin.* calls, and scheduled jobs.
# NEVER use this for handling a user's data request — use get_authed_client instead.
supabase: Client = _force_http1(
    create_client(
        settings.supabase_url,
        settings.supabase_service_role_key,
    )
)


def get_authed_client(access_token: str) -> Client:
    """
    Builds a Supabase client scoped to the user's JWT so that Row Level Security
    policies are enforced on every query. This is the real multi-tenant guard:
    even if a query forgets its org_id filter, RLS prevents cross-org access.
    """
    client = _force_http1(create_client(settings.supabase_url, settings.supabase_anon_key))
    client.postgrest.auth(access_token)
    return client
