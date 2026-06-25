# Frontend

Internal wiki for new engineers joining the Horus frontend.

---

## Tech stack

| Tool | Version | Purpose |
|---|---|---|
| React | 18.3 | UI framework |
| TypeScript | 5.6 | Type safety |
| Vite | 5.4 | Dev server and bundler |
| React Router | 6.27 | Client-side routing |
| Tailwind CSS | 3.4 | Utility-class styling |
| Supabase JS | 2.46 | Auth and realtime |
| `@supabase/auth-ui-react` | 0.4 | Pre-built login form |
| Recharts | 2.13 | Charts (posture timeline) |
| Radix UI (Dialog, Popover) | 1.1 | Accessible primitives |
| Lucide React | 0.453 | Icon set |
| date-fns | 4.1 | Date formatting |
| cronstrue | 3.14 | Human-readable cron expressions |
| vite-plugin-pwa | 0.21 | Progressive Web App manifest |

The frontend is deployed to Cloudflare Pages (`wrangler` is in devDependencies). Vite proxies `/api` requests to the FastAPI backend in development.

---

## Directory structure

```
frontend/
  src/
    App.tsx               # Route tree, PrivateRoute, SessionWatcher
    main.tsx              # React root, UserProvider, ErrorBoundary
    pages/                # One file per route
    components/
      layout/             # Layout, Sidebar, Header
      findings/           # FindingCard, SeverityBadge
      assets/             # AssetList, AssetForm
      incidents/          # IncidentBadges
      agents/             # IrisAiModal
      CommandPalette.tsx
      GlassCard.tsx
      Modal.tsx
      ImportModal.tsx
      PostureTimeline.tsx
      ShortcutsOverlay.tsx
      ErrorBoundary.tsx
    contexts/
      UserContext.tsx      # Auth state, role, org
    hooks/
      useAuth.ts          # Re-export alias for useUser
      useRole.ts          # Re-export alias for useUser
      useAssets.ts        # Fetch and refresh asset list
      useRealtime.ts      # Supabase postgres_changes subscription
    lib/
      api.ts              # Typed fetch wrapper + endpoint helpers
      supabase.ts         # Supabase client singleton
      utils.ts            # cn(), severityBg(), severityColor()
```

---

## Route structure

All routes under `/` are wrapped in `PrivateRoute`, which renders `Layout` (sidebar + header) as their parent via React Router's nested route / `Outlet` pattern. Public routes (`/login`, `/change-password`, `/preview`) render outside the layout.

Every page component is lazy-loaded: `const Foo = lazy(() => import('./pages/Foo'))`. The initial bundle only includes the shell and auth code.

| Path | Page | Access |
|---|---|---|
| `/login` | Login | Public |
| `/change-password` | ChangePassword | Requires session (no password-change gate) |
| `/preview` | StylePreview | Public |
| `/` | Redirect to `/dashboard` | Private |
| `/dashboard` | Dashboard | All roles |
| `/assets` | Assets | All roles |
| `/assets/:id` | AssetDetail | All roles |
| `/discovery` | Discovery | All roles |
| `/watchtower` | Watchtower | All roles |
| `/iris` | Iris | All roles |
| `/cloud` | CloudSecurity | Admin only |
| `/scans` | Scans | All roles |
| `/scans/:id` | ScanDetail | All roles |
| `/schedules` | Schedules | All roles |
| `/jobs` | Jobs | All roles |
| `/findings` | Findings | All roles |
| `/findings/:id` | FindingDetail | All roles |
| `/incidents` | Incidents | All roles |
| `/incidents/:id` | IncidentDetail | All roles |
| `/adversarial` | Adversarial | All roles |
| `/adversarial/:id` | AdversarialDetail | All roles |
| `/auth-phishing` | AuthPhishing (Phishing Campaigns) | Admin only |
| `/credential-exposure` | CredentialExposure | Admin only |
| `/permissions` | Permissions | All roles |
| `/team` | Team | All roles |
| `/audit` | Audit | Admin only |
| `/integrations` | Integrations | Admin only (enforced in page) |
| `/settings` | Settings | All roles |
| `/analytics` | Analytics | All roles |
| `/red-blue` | Redirect to `/adversarial` | Legacy |
| `/audit-log` | Redirect to `/audit` | Legacy |

Role-gated sidebar links filter out entries where `minRole` exceeds the user's role. The pages themselves also enforce access (e.g. Integrations renders an access-denied message for non-admins).

---

## Page inventory

**Dashboard** (`/dashboard`): Security operations overview showing KPI cards (Act Now, KEV Exposure, Asset Coverage, MTTR), a findings trend row, an SSVC priority breakdown, the posture timeline chart, top risky assets, recent scans, and recent findings. The widget set is user-customizable with visibility persisted to `localStorage`.

**Assets** (`/assets`): Asset list with an inline "Add Asset" form. Delegates rendering to `AssetList` and `AssetForm` components.

**AssetDetail** (`/assets/:id`): Per-asset detail view showing metadata, scan history, and associated findings.

**Discovery** (`/discovery`): Network discovery feature for finding new assets on a subnet.

**Watchtower** (`/watchtower`): Continuous exposure monitoring in three panels: KEV-based active-exploitation alerts (streamed via SSE), ransomware victim monitoring (Ransomware.live), dark web intelligence search (IntelligenceX), and IOC lookups (ThreatFox + URLhaus).

**Iris** (`/iris`): Manages lightweight host agents (the Iris daemon). Lists registered agents with online/degraded/offline status derived from `last_seen_at`. Allows registering a new agent (shows a one-time API key and install command), viewing the last 50 events per agent in a slide-in panel, and triggering AI triage. The AI triage interval is configurable and saved to the org settings.

**CloudSecurity** (`/cloud`): Cloud security posture management (admin-only).

**Scans** (`/scans`): List of all scans with status filtering.

**ScanDetail** (`/scans/:id`): Full scan results including findings breakdown.

**Schedules** (`/schedules`): Recurring scan schedule management with cron expressions.

**Jobs** (`/jobs`): Background job history for scans and scheduled tasks.

**Findings** (`/findings`): Filterable, paginated findings list. Filters: severity, status, asset, CVE ID, tool, and sort order. Findings correlated from a detected service are grouped in a collapsible `ServiceGroup`. Supports bulk status actions (mark false positive, accept risk, mark resolved, mark open). Noise (absence-of-finding) results are hidden by default behind a toggle banner. Export to JSONL or CSV. Import via `ImportModal`.

**FindingDetail** (`/findings/:id`): Full finding detail including SSVC metadata, remediation suggestions, and timeline.

**Incidents** (`/incidents`): Case management for grouping related findings. Shows open/critical/overdue-SLA stats. Filterable by status and severity. Create incident modal with title, severity, SLA deadline, assignee, and description.

**IncidentDetail** (`/incidents/:id`): Full incident view with linked findings and timeline.

**Adversarial** (`/adversarial`): Red/Blue team exercise management (formerly `/red-blue`).

**AdversarialDetail** (`/adversarial/:id`): Detail view for a specific red/blue exercise.

**AuthPhishing** (`/auth-phishing`): Phishing simulation campaigns (admin-only). Two tabs: Campaigns (list, create via 4-step wizard: Setup, Assets, Targets, Review) and Contacts (individual add or CSV import). Tracks click rate and report rate per campaign and per target.

**CredentialExposure** (`/credential-exposure`): Monitors for leaked credentials related to the org's domains (admin-only).

**Permissions** (`/permissions`): Role and permission management UI.

**Team** (`/team`): Team member list and invite management.

**Audit** (`/audit`): Immutable audit log of all platform events (admin-only).

**Integrations** (`/integrations`): Notification and ticketing integrations (admin-only). Supports Slack, Microsoft Teams, Email (with optional monthly board-report PDF), PagerDuty, OpsGenie, Jira, and outgoing webhooks. Each integration can be toggled enabled/disabled and tested in place.

**Settings** (`/settings`): Org-level settings including LLM configuration and API keys.

**Analytics** (`/analytics`): Security metrics and trend analysis charts.

**ChangePassword** (`/change-password`): Forced password change screen. Uses `RequireUser` (not `PrivateRoute`) so it is reachable even when `mustChangePassword` is true.

**StylePreview** (`/preview`): Public, unstyled showcase of the Horus liquid-glass visual direction. Useful for design QA.

---

## Layout system

### Shell

`Layout.tsx` renders the persistent application chrome: `Sidebar` on the left, `Header` at the top (sticky), and a scrollable `<main>` that renders the current page via `<Outlet />`. Each route transition re-keys the `<div>` around the outlet so a CSS `animate-page-enter` entrance animation replays.

`CommandPalette` is mounted inside `Layout` and is always present in the DOM (it renders `null` when closed).

### Sidebar

`Sidebar.tsx` is a 240 px wide panel. On mobile it is a fixed overlay drawer (slides in/out with a 300 ms CSS transition and a backdrop). On `md` and above it is a static column. The drawer closes automatically on route change and on `Escape`.

Navigation links are defined as a static array. Links with a `minRole` are filtered out at render time using `can()` from `useRole`.

### Header

`Header.tsx` renders:
- A hamburger button (mobile only) that opens the sidebar
- A search trigger button that dispatches `PALETTE_TOGGLE_EVENT` and shows the `⌘K` / `Ctrl+K` shortcut hint
- A notification bell (polls `/notifications` every 60 seconds via `setInterval`, uses a Radix `Popover`)
- The signed-in user's email
- A sign-out button

---

## State management

There is no Redux or Zustand. State lives at three levels:

1. **Server state**: fetched in each page component with `useEffect` + the `api` helper. There is no global cache layer; pages fetch their own data independently.

2. **Auth and user context**: `UserContext` (described below) holds the Supabase session, the user's role, and their `org_id`. Everything else that needs these values reads them via `useAuth()` or `useRole()` (both re-export `useUser` for backward compatibility).

3. **Local UI state**: `useState` inside page and component files.

### Data fetching pattern

```ts
// Typical pattern in a page component
const [data, setData] = useState<Foo[]>([])
const [loading, setLoading] = useState(true)

const load = () => {
  setLoading(true)
  api.get<Foo[]>('/foo').then(setData).finally(() => setLoading(false))
}
useEffect(load, [/* filter deps */])
```

The `api` object in `src/lib/api.ts` is a typed wrapper around `fetch`. It reads the Supabase JWT from the active session and attaches it as `Authorization: Bearer <token>`. A session-expired callback (`setSessionExpiredHandler`) lets `SessionWatcher` (mounted in `App`) redirect to `/login?expired=1` when the API returns a 401.

---

## Contexts

### UserContext (`src/contexts/UserContext.tsx`)

The only React context in the codebase. It wraps the entire app via `UserProvider` in `main.tsx`.

**What it exposes:**

| Field | Type | Description |
|---|---|---|
| `user` | `User \| null` | Supabase auth user object |
| `role` | `'admin' \| 'analyst' \| 'viewer' \| null` | Role from the `profiles` table |
| `orgId` | `string \| null` | The user's organisation UUID |
| `hasProfile` | `boolean` | Whether a `profiles` row exists for this user |
| `mustChangePassword` | `boolean` | Forces redirect to `/change-password` |
| `loading` | `boolean` | True until the initial session and profile fetch resolve |
| `can(minimum)` | `(Role) => boolean` | Hierarchy check: `viewer < analyst < admin` |
| `refreshProfile()` | `() => Promise<void>` | Re-fetches the profile row (e.g. after a role change) |
| `signOut()` | `() => void` | Calls `supabase.auth.signOut()` |

**How it works:** On mount, `getSession()` fetches the current session. If a user is found, `loadProfile()` queries `profiles` for `role`, `org_id`, and `must_change_password`. `onAuthStateChange` keeps everything in sync across tabs and after token refresh.

---

## Hooks

### `useAuth` / `useRole`

Both are trivial re-exports of `useUser` kept for naming clarity at the call site. `useAuth` is used in places that care about the session; `useRole` in places that only need `can()`.

### `useAssets`

Fetches `GET /assets` on mount and exposes `{ assets, loading, error, refresh }`. Used by Findings (for the asset filter dropdown) and Assets page.

### `useRealtime`

Subscribes to Supabase Realtime `postgres_changes` for a given table filtered by `org_id`. Accepts optional `onInsert` and `onUpdate` callbacks. Used in Dashboard to refresh metrics when a scan completes or a new finding arrives without polling.

```ts
useRealtime('agent_runs', orgId, onRefresh)
useRealtime('findings', orgId, onInsert, onUpdate)
```

---

## Key reusable components

### `CommandPalette`

Keyboard-driven search and navigation overlay. Triggered by `⌘K` / `Ctrl+K` or by dispatching `PALETTE_TOGGLE_EVENT`. Opens as a modal with a search input. Without a query it lists all accessible pages. With a query it searches pages by label and lazily-loaded assets, findings, and scans. Fully keyboard-navigable (up/down arrows, Enter to navigate, Escape to close).

### `Modal`

Accessible modal dialog built on Radix UI `Dialog`. Provides a focus trap, scroll lock, Escape-to-close, and backdrop-click-to-close. Accepts `open`, `onClose`, `title`, `children`, and a `className` override for panel width.

### `GlassCard`

Surface primitive for the liquid-glass visual direction. Renders a `div` with the `glass specular rounded-2xl` classes. Pass `interactive` for a hover lift/glow effect.

### `ShortcutsOverlay`

Hold-Shift keyboard shortcut system. While Shift is held (outside inputs), every visible button and link on screen gets a letter badge. Pressing that letter fires a click. Useful for power users navigating dense pages without lifting hands from the keyboard.

### `PostureTimeline`

Recharts area chart showing the org's security posture score over time, fetched from `/dashboard/posture-timeline`. Rendered at the bottom of the Dashboard.

### `ErrorBoundary`

Standard React error boundary wrapping the entire app. Catches render-time exceptions and prevents a blank screen.

### `ImportModal`

Reusable modal for importing findings from a JSON/JSONL file. Used on the Findings page.

---

## Authentication flow

### Normal login

1. User lands on `/login`.
2. The `Auth` component from `@supabase/auth-ui-react` renders an email/password form.
3. On successful sign-in, Supabase fires `SIGNED_IN` via `onAuthStateChange`.
4. `Login.tsx` listens for that event and calls `navigate('/dashboard')`.
5. `UserContext` also listens via its own `onAuthStateChange` subscriber and loads the user's profile.

### Demo mode

The landing page links to `/login?demo=1`. When `isDemo` is detected, `Login.tsx` silently calls `supabase.auth.signInWithPassword` with the publicly-documented demo credentials (`demo@horusagents.com` / `HorusDemo2026!`). The demo account has `viewer` role so the backend blocks all write operations.

### Session persistence

Supabase JS handles token refresh automatically. On page load, `getSession()` in `UserContext` rehydrates the session from `localStorage`. No additional work is needed.

### Expired session handling

`SessionWatcher` (mounted in `App.tsx`) registers a callback with `setSessionExpiredHandler`. When the `api` helper receives a 401, it calls that callback, which calls `signOut()` and redirects to `/login?expired=1`. The login page shows an amber banner when the `expired=1` query parameter is present.

### Forced password change

If `profiles.must_change_password` is `true`, `PrivateRoute` redirects to `/change-password` before rendering any other page. `RequireUser` (used only by `/change-password` itself) skips that gate so the page stays reachable.

---

## Environment variables

| Variable | Where used | Description |
|---|---|---|
| `VITE_SUPABASE_URL` | `src/lib/supabase.ts` | Supabase project URL |
| `VITE_SUPABASE_ANON_KEY` | `src/lib/supabase.ts` | Supabase anon (public) key |
| `VITE_API_URL` | Some pages (Watchtower SSE) | Full URL of the backend API. Defaults to `/api` (same-origin). |
| `VITE_API_BASE_URL` | `src/pages/Iris.tsx` | Base URL for Iris install scripts. Falls back to the origin at runtime. |
| `VITE_API_PROXY_TARGET` | `vite.config.ts` | Backend URL for Vite's `/api` proxy. Defaults to `http://localhost:8000`. Set to `http://backend:8000` in Docker Compose. |

In production, `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` are the only required variables. `VITE_API_URL` is only needed if the frontend and backend are on different origins. These are set as Cloudflare Pages environment variables in the dashboard.

---

## Build and dev commands

All commands are run from the `frontend/` directory.

```bash
# Start the dev server at http://localhost:5173
# Proxies /api to http://localhost:8000 (or $VITE_API_PROXY_TARGET)
npm run dev

# Type-check and build for production (outputs to dist/)
npm run build

# Serve the production build locally (mirrors production headers)
npm run preview
```

TypeScript strict mode is enabled. `npm run build` runs `tsc -b` before Vite builds, so type errors fail the build.

The Vite config applies a CSP and security headers during dev and `preview`. A production static host (Cloudflare Pages) must set those headers independently as HTTP response headers, not via meta tags.

The PWA plugin registers a service worker and generates a web manifest so the app is installable as a standalone app from Chrome/Edge.
