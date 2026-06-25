# Security and Authentication Runbook

This document covers every security boundary in Horus: how requests are authenticated, how data is isolated between organizations, how the API is hardened against abuse, and how sensitive data is handled before it leaves the process.

---

## 1. Authentication

### Supabase Auth (JWT)

Horus delegates credential management to Supabase Auth (GoTrue). Users authenticate via the Supabase client, which returns a signed JWT. That JWT is a short-lived access token issued by Supabase's Auth server and signed with a key Horus never holds directly.

The backend accepts two credential types on every protected endpoint:

- `Authorization: Bearer <jwt>` for human users (browser sessions)
- `X-Api-Key: hrs_...` for programmatic access (see Section 3)

If both headers are present, the API key takes precedence.

### JWT validation in the backend

Validation happens in `backend/api/auth.py` inside `_resolve_user()`. The token is validated on **every request** by calling `supabase.auth.get_user(token)`. This is the only call that can detect a revoked or expired token; it is never skipped or cached.

What is cached: after JWT validation succeeds, the database lookup for the user's profile (`org_id`, `role`, `must_change_password`) is stored in a per-process in-memory dictionary with a 30-second TTL. A stale cache entry can never let an invalidated JWT through; only the profile metadata (role, org) is deferred.

```
Request
  -> supabase.auth.get_user(token)   # always live, catches revocation
  -> profiles lookup (cached 30s)    # org_id, role, must_change_password
  -> return user dict
```

The cache is keyed by `user.id` and can be manually invalidated with `evict_user_sessions(user_id)`, which is called after a password change.

### Forced password change

When an admin invites a user, the profile is created with `must_change_password = true`. The gate is enforced server-side in `get_current_user()`, not only in the React router. Any request to any endpoint other than `/account/change-password` from a user with that flag set returns `403 Password change required`. This prevents a user with a temporary password from calling any API endpoint directly via curl or Postman before completing onboarding.

### SSE / EventSource authentication

Server-Sent Events endpoints cannot carry an `Authorization` header because the browser's `EventSource` API does not support custom headers. The solution is a short-lived single-use stream ticket:

1. The client calls a regular authenticated endpoint to obtain a ticket (`mint_stream_ticket`).
2. The ticket (a 32-byte URL-safe random string) is passed as a query parameter.
3. On the SSE endpoint, `consume_stream_ticket` validates and immediately deletes the ticket (single-use).
4. Tickets expire after 30 seconds even if unused.

A leaked ticket in a proxy or access log is worthless: it cannot be used a second time and expires in seconds. Tickets are stored in-process; if you ever run multiple workers, move ticket storage to Redis.

### Onboarding path

`get_authenticated_user()` is a lighter dependency used only during the onboarding flow. It validates the JWT but does not require an existing profile, because a freshly signed-up user has a valid session but no profile or organization yet. It returns only `{id, email, token}`.

---

## 2. Authorization

### Role hierarchy

Three roles exist, ordered by privilege:

| Role     | Level | Description                                    |
|----------|-------|------------------------------------------------|
| viewer   | 0     | Read-only access                               |
| analyst  | 1     | Can trigger scans and create findings          |
| admin    | 2     | Full access: team management, API keys, config |

The hierarchy is defined in `backend/api/deps.py`:

```python
ROLE_HIERARCHY = {"viewer": 0, "analyst": 1, "admin": 2}
```

`require_role("analyst")` is a FastAPI dependency factory. It rejects the request with `403` if the user's level is below the minimum required. Usage: `Depends(require_role("admin"))`.

### Org-scoped access

Every user belongs to exactly one organization (`org_id` on the `profiles` table). This field is set at the service-role level during invite and cannot be changed through the user-scoped API. Every database query in the application code filters by `user["org_id"]`, and RLS policies at the database level enforce the same boundary as a second line of defense (see Section 4).

### Injecting the current user

`get_current_user()` in `backend/api/auth.py` is the FastAPI dependency that resolves the authenticated principal. It accepts either a Bearer JWT or an `X-Api-Key` header, validates credentials, and returns a uniform user dict:

```python
{
  "id": str,          # auth.uid() for JWT users, "apikey:<uuid>" for API keys
  "email": str,       # absent for API keys
  "org_id": str,      # always present
  "role": str,        # admin | analyst | viewer
  "token": str,       # original credential (JWT or key)
  "is_api_key": bool, # True only for API key requests
}
```

Route handlers declare `user = Depends(get_current_user)` or `user = Depends(require_role("admin"))`. There is no global authenticated-by-default behavior; every protected route must explicitly declare the dependency.

### Privileged writes go through the service-role client

Profile mutations (invite, role change, soft-delete, clearing `must_change_password`) are performed using the Supabase service-role key, which bypasses RLS. The `profiles` table's RLS policy for the user-scoped client is `FOR SELECT` only (see Section 4), so a regular authenticated user cannot UPDATE their own role or any other member's fields.

---

## 3. API Keys

API keys are long-lived credentials intended for service integrations and exporters. They are managed exclusively by organization admins.

### Format and storage

Keys follow the format `hrs_<32 random alphanumeric characters>` (total length 36 characters). The prefix `hrs_` makes them easy to identify and block in secret scanning tools.

The backend stores only the SHA-256 hash of the full key. The plaintext secret is returned exactly once, at creation time, and is never stored or retrievable again. The first 12 characters of the key (`hrs_<8 chars>`) are stored as `key_prefix` for display in the management UI.

### Scopes (roles)

An API key is assigned a role at creation time: `analyst` or `admin`. The role is enforced identically to the JWT role: `require_role("admin")` rejects an analyst-scoped key with `403`.

### Authentication flow

1. Client sends `X-Api-Key: hrs_...` header.
2. `_resolve_api_key()` computes `sha256(key)` and queries `api_keys` for a matching hash where `revoked_at IS NULL`.
3. If found, it updates `last_used_at` asynchronously (best-effort; does not block the request).
4. Returns a user dict with `is_api_key: true`, `org_id` and `role` from the key row.
5. The resulting principal is indistinguishable from a JWT user for all downstream authorization checks.

### Database client for API key requests

Because API keys do not carry a JWT, `get_db()` cannot construct a user-scoped Supabase client for them. Instead it returns the admin (`service_role`) Supabase client. Data isolation is still enforced: all query code filters explicitly by `user["org_id"]`. RLS policies are bypassed for the service-role client; the application-level `org_id` filter is the sole isolation mechanism for API key requests.

### Revocation

`DELETE /api/api-keys/{key_id}` sets `revoked_at` to the current timestamp. All lookups filter `revoked_at IS NULL`, so revocation is immediate. Keys are never physically deleted.

### Management permissions

Only admins can list, create, or revoke API keys. This is enforced at the route level by `_assert_admin(user)` before any database operation.

---

## 4. Row Level Security

### Pattern

Every user-facing table has RLS enabled. The core pattern uses a helper function `current_org_id()` that reads the `org_id` from the `profiles` table for the current authenticated user:

```sql
create or replace function current_org_id()
  returns uuid
  language sql
  security definer
  set search_path = public
as $$
  select org_id from profiles where id = auth.uid()
$$;
```

The `security definer` attribute and the pinned `search_path = public` are both required: without the fixed search path, a maliciously named `profiles` object in another schema could intercept the lookup (migration `20260622091000`).

### org_isolation policy

Most tables have a single `org_isolation` policy (`FOR ALL`) applied as:

```sql
using (org_id = current_org_id() and deleted_at is null)
with check (org_id = current_org_id())
```

The `USING` clause filters reads and the `WITH CHECK` clause gates writes. The `deleted_at IS NULL` condition in `USING` means soft-deleted rows are invisible to authenticated users without any change to application query code. The `WITH CHECK` intentionally omits `deleted_at IS NULL` so the application can still write a `deleted_at` timestamp on UPDATE (the soft-delete operation itself).

Tables covered by `org_isolation`:

- `assets`
- `findings`
- `scans`
- `scan_schedules`
- `agent_runs`
- `agent_executions`
- `agent_suggestions`
- `permission_policies`
- `integrations`
- `audit_log`
- `api_keys`
- `red_findings`
- `iris_agents`
- `discovery_sources`
- `employees`
- `phishing_campaigns`
- `phishing_templates` (org_isolation + a public-read policy for `is_public = true` rows)
- `incident_findings` (org scope derived through parent `incidents` row)
- `adversarial_schedules` (split into admin-manage and member-read policies)

### profiles table

The `profiles` table is special. The user-scoped RLS policy is `FOR SELECT` only:

```sql
create policy "org_read" on profiles
  for select
  using (org_id = current_org_id() and deleted_at is null);
```

This prevents any authenticated user from updating their own `role`, `org_id`, or any other profile field through the user-scoped client. All profile mutations are performed using the service-role key, which bypasses RLS. This policy was introduced specifically to fix a privilege escalation vector (migration `005_fix_profiles_privesc.sql`).

### organizations table

Users can read their own organization row:

```sql
create policy "own_org" on organizations
  using (id = current_org_id());
```

### notifications table

Notifications are user-scoped rather than org-scoped:

```sql
create policy "own_notifications" on notifications
  using (user_id = auth.uid() and deleted_at is null)
  with check (user_id = auth.uid());
```

### Recovery

Soft-deleted rows are invisible to all user-scoped clients. Recovery requires either the service-role key or a direct SQL connection, both of which bypass RLS.

---

## 5. Rate Limiting

Rate limiting is implemented as a Starlette middleware in `backend/main.py` and applies to all paths under `/api`.

### Limits

Two budgets are enforced:

- **Global per-IP:** `settings.rate_limit_per_minute` requests per 60-second window, applied to every `/api` request.
- **Sensitive per-IP:** `settings.rate_limit_sensitive_per_minute` requests per window, applied as an additional budget to write operations on abuse-prone endpoints:
  - `POST /api/scans` (scan trigger)
  - `POST /api/team/invite` (team invite)

A request to a sensitive endpoint consumes one token from both budgets.

### Algorithm

The limiter uses a sliding window algorithm. The window slides continuously rather than resetting at fixed intervals, which prevents burst abuse at window boundaries.

### Backends

The `build_limiter()` factory selects the backend based on `REDIS_URL`:

| Condition | Backend | Behavior |
|-----------|---------|----------|
| `REDIS_URL` set and Redis reachable | `RedisWindowLimiter` | Atomic via Lua script on sorted sets; shared across all workers. State survives worker restarts. |
| `REDIS_URL` unset or Redis unreachable | `SlidingWindowLimiter` | Per-process in-memory deque. Each worker enforces its own budget independently. |

The Redis implementation uses an atomic Lua script to avoid race conditions under concurrent workers. If Redis becomes unreachable after startup, the factory logs a warning and falls back to in-memory; it does not crash the process.

### IP resolution

The client IP is derived in `client_ip_from()`:

- If `settings.trust_proxy_headers` is `True`, the first address in `X-Forwarded-For` is used.
- Otherwise (the default), `request.client.host` is used directly.

`X-Forwarded-For` is only trusted when `trust_proxy_headers` is explicitly enabled because the header is client-spoofable when not sitting behind a trusted reverse proxy.

### 429 response format

```json
{
  "detail": "Rate limit exceeded. Slow down."
}
```

Response headers:

```
HTTP/1.1 429 Too Many Requests
Retry-After: <seconds>
```

`Retry-After` is always an integer (minimum 1), rounded from the computed retry window.

### Login endpoint

Login itself is handled by Supabase Auth (GoTrue), which has its own throttling. The Horus rate limiter does not wrap the Supabase Auth endpoints.

---

## 6. Security Headers

Headers are set in `backend/core/security_headers.py` and applied to every response by the `security_headers` middleware in `main.py` (using `setdefault` so a route's explicit header is never overwritten).

### Headers applied in all environments

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME type sniffing; responses are taken at their declared `Content-Type`. |
| `X-Frame-Options` | `DENY` | Prevents the API from being embedded in an iframe (clickjacking protection). |
| `Referrer-Policy` | `no-referrer` | Prevents the API URL (which may carry IDs) from leaking to other origins via the Referer header. |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | The API serves only JSON; nothing should be loaded from a response. `frame-ancestors 'none'` is the CSP-level equivalent of `X-Frame-Options: DENY`. |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates the browsing context group, required for certain cross-origin attack mitigations. |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=(), payment=()` | Disables access to sensitive browser features by default. |

### Headers applied in non-development environments only

| Header | Value | Purpose |
|--------|-------|---------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Enforces HTTPS for one year including all subdomains. Omitted in development to avoid locking localhost to HTTPS after a single visit. |

---

## 7. Input Validation

`backend/core/validation.py` implements deterministic triage for security findings before they enter the AI validation pipeline.

The module provides `auto_verdict()`, which assigns a verdict without spending an LLM call when the outcome is already certain:

| Condition | Verdict |
|-----------|---------|
| `exploitability == "active"` (CISA KEV) | `confirmed` |
| `severity == "info"` | `needs_verification` |
| `confidence >= 0.9` | `confirmed` |
| `confidence <= 0.2` and no exploitation signal | `needs_verification` |
| All other cases | `None` (go to red/blue debate) |

This gate prevents unnecessary LLM calls on findings that are trivially noise or trivially confirmed, and avoids wasting a debate on a KEV-active finding that is real by definition.

The four verdict levels in order of confidence: `false_positive`, `needs_verification`, `likely`, `confirmed`.

`confidence_for_verdict()` enforces consistent confidence floors and ceilings per verdict label so persisted confidence values stay coherent with the verdict text.

---

## 8. PII Redaction

`backend/core/redaction.py` pseudonymizes sensitive identifiers before they are included in any prompt sent to an external LLM.

### Why

Horus is a security platform. Sending an organization's actual hostnames, IP addresses, and email addresses to an external model would expose the infrastructure map. The redaction layer shrinks the blast radius of provider trust: the model reasons over product names, versions, severities, and CVE identifiers (which are public), never over the customer's actual asset identifiers.

### What is redacted

The `Redactor` class maintains a stable bidirectional map between real values and placeholders. The same value always maps to the same placeholder within one instance:

| Pattern | Placeholder format | Example |
|---------|--------------------|---------|
| Asset hostname/name (seeded explicitly) | `[HOST_n]`, `[NAME_n]` | `[HOST_1]` |
| IPv4 addresses (regex auto-detected) | `[IP_n]` | `[IP_2]` |
| Email addresses (regex auto-detected) | `[EMAIL_n]` | `[EMAIL_1]` |
| FQDNs (regex auto-detected, allowlist excepted) | `[HOST_n]` | `[HOST_3]` |

### What is not redacted

Public reference domains are explicitly allowed through and appear in the clear in prompts:

```
nvd.nist.gov, cisa.gov, mitre.org, first.org, cve.org, github.com,
nginx.org, apache.org, openssl.org, kb.cert.org, exploit-db.com
```

This preserves real CVE and advisory links in both the prompt and the restored output.

### Workflow

```
real prompt text
    -> Redactor.redact()   # seeds applied longest-first, then regex patterns
    -> [HOST_1], [IP_1]... in prompt
    -> LLM call
    -> Redactor.restore()  # placeholders replaced back with real values
    -> real values in persisted finding output
```

Restoration happens before findings are written to the database, so stored findings read naturally with real hostnames.

### Limitations

This is pseudonymization, not encryption. It reduces exposure but does not eliminate the need to trust the LLM provider. An identifier that was not seeded and does not match the regex patterns could slip through. For environments requiring zero data exposure to cloud providers, a no-cloud or TEE deployment tier is the appropriate control.

Seeds shorter than 4 characters are not applied to avoid clobbering common short words (e.g., an asset named "web" would incorrectly mask every occurrence of that word).

---

## 9. Soft Deletes and Audit Trail

### Soft delete policy

No user-managed record is ever physically deleted through the API. Every user-facing table has a `deleted_at timestamptz` column. A "delete" operation sets this timestamp to the current UTC time.

RLS `USING` clauses include `deleted_at IS NULL`, so soft-deleted rows are invisible to all user-scoped queries. The application code requires no change: any `SELECT` through the authed client automatically excludes soft-deleted rows.

Tables covered:

`assets`, `permission_policies`, `scan_schedules`, `integrations`, `discovery_sources`, `employees`, `phishing_campaigns`, `phishing_templates`, `red_findings`, `iris_agents`, `incident_findings`, `notifications`, `profiles`, `adversarial_schedules`

API keys use `revoked_at` instead of `deleted_at` (same pattern, different column name). The `organizations` table uses hard delete (intentional).

### Recovery

Recovering a soft-deleted record requires the service-role key or direct database access, both of which bypass RLS. There is no user-facing recovery endpoint.

### Audit log

All significant mutations are recorded in the `audit_log` table via `backend/core/audit.log_action()`. Each entry records:

- `org_id`: the organization context
- `actor_type`: `user`, `agent`, or `system`
- `actor_id`: the user ID, API key ID, or agent identifier
- `action`: a dot-separated event name (e.g., `permission_policy.created`)
- `entity_type` and `entity_id`: the affected object
- `metadata`: a JSONB payload with before/after values or relevant context
- `created_at`: immutable timestamp

The audit log is append-only through the API. The `audit_log` RLS policy scopes reads to the current org; no policy permits DELETE or UPDATE through the user-scoped client, so entries cannot be retroactively modified by an application-level actor.
