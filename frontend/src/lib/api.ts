import { supabase } from './supabase'

export class ApiError extends Error {
  status: number
  retryAfter: number | null

  constructor(message: string, status: number, retryAfter: number | null = null) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.retryAfter = retryAfter
  }
}

// Registered by the app shell so an unrecoverable auth failure can route the
// user to /login with a friendly notice instead of surfacing a raw error.
let sessionExpiredHandler: (() => void) | null = null
export function setSessionExpiredHandler(handler: () => void) {
  sessionExpiredHandler = handler
}

// Registered by the app shell so a 402 (subscription lapsed past grace) routes the user
// to the billing-inactive screen instead of surfacing a raw error on every request.
let billingSuspendedHandler: (() => void) | null = null
export function setBillingSuspendedHandler(handler: () => void) {
  billingSuspendedHandler = handler
}

let expiredHandled = false
// Re-arm the guard once a fresh session exists, so a later expiry is handled again.
supabase.auth.onAuthStateChange((event) => {
  if (event === 'SIGNED_IN' || event === 'TOKEN_REFRESHED') expiredHandled = false
})

function handleSessionExpired() {
  if (expiredHandled) return // avoid a redirect storm when many requests 401 at once
  expiredHandled = true
  if (sessionExpiredHandler) {
    sessionExpiredHandler()
  } else {
    // Fallback if the app shell hasn't registered a handler yet.
    void supabase.auth.signOut()
    window.location.assign('/login?expired=1')
  }
}

async function authHeaders(): Promise<HeadersInit> {
  const { data } = await supabase.auth.getSession()
  const token = data.session?.access_token
  return token ? { Authorization: `Bearer ${token}` } : {}
}

// Fetches /api with the current access token. On a 401 it transparently refreshes
// the session once and retries; if the refresh fails the user is sent to re-auth.
async function authedFetch(path: string, init: RequestInit, retried = false): Promise<Response> {
  const headers = await authHeaders()
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { ...(init.headers ?? {}), ...headers },
  })

  if (res.status === 401 && !retried) {
    const { data, error } = await supabase.auth.refreshSession()
    if (!error && data.session) {
      return authedFetch(path, init, true)
    }
    handleSessionExpired()
  }
  return res
}

function retryAfterSeconds(value: string | null): number | null {
  if (!value) return null
  const seconds = Number(value)
  if (Number.isFinite(seconds) && seconds > 0) return Math.ceil(seconds)

  const retryDate = Date.parse(value)
  if (Number.isNaN(retryDate)) return null
  return Math.max(1, Math.ceil((retryDate - Date.now()) / 1000))
}

export function friendlyErrorMessage(error: unknown, fallback = 'Request failed'): string {
  if (error instanceof ApiError && error.status === 429) {
    const wait = error.retryAfter ? ` Try again in ${error.retryAfter} seconds.` : ' Try again in a moment.'
    return `Too many requests.${wait}`
  }
  if (error instanceof ApiError && error.status === 401) {
    return 'Your session expired. Please sign in again.'
  }
  if (error instanceof Error) return error.message
  return fallback
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await authedFetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers ?? {}) },
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    const message = typeof body.detail === 'string' ? body.detail : `HTTP ${res.status}`
    // 402 = the org's subscription lapsed past the grace period. Route to the billing
    // screen (the /billing/portal call there is exempt server-side, so it won't loop).
    if (res.status === 402 && billingSuspendedHandler && !path.startsWith('/billing/')) {
      billingSuspendedHandler()
    }
    throw new ApiError(message, res.status, retryAfterSeconds(res.headers.get('Retry-After')))
  }
  if (res.status === 204) return undefined as T
  return res.json()
}

/** Fetch a binary attachment and trigger a browser download. The filename is taken from the
 *  server's Content-Disposition when present, otherwise `fallbackName`. */
async function download(path: string, fallbackName: string): Promise<void> {
  const res = await authedFetch(path, {})
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    const message = typeof body.detail === 'string' ? body.detail : `HTTP ${res.status}`
    throw new ApiError(message, res.status, retryAfterSeconds(res.headers.get('Retry-After')))
  }

  const disposition = res.headers.get('Content-Disposition') ?? ''
  const match = disposition.match(/filename="?([^"]+)"?/)
  const name = match?.[1] ?? fallbackName

  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

const getCache = new Map<string, { time: number, promise: Promise<any> }>()

export const api = {
  get: <T>(path: string, ttlMs = 5000): Promise<T> => {
    const now = Date.now()
    const cached = getCache.get(path)
    if (cached && (now - cached.time) < ttlMs) {
      return cached.promise as Promise<T>
    }
    const promise = request<T>(path)
    getCache.set(path, { time: now, promise })
    promise.catch(() => getCache.delete(path))
    return promise
  },
  post: <T>(path: string, body?: unknown) => {
    getCache.clear()
    return request<T>(path, { method: 'POST', body: JSON.stringify(body) })
  },
  put: <T>(path: string, body?: unknown) => {
    getCache.clear()
    return request<T>(path, { method: 'PUT', body: JSON.stringify(body) })
  },
  patch: <T>(path: string, body?: unknown) => {
    getCache.clear()
    return request<T>(path, { method: 'PATCH', body: JSON.stringify(body) })
  },
  delete: <T>(path: string) => {
    getCache.clear()
    return request<T>(path, { method: 'DELETE' })
  },
  download,
}

// ── BreachDirectory credential check ─────────────────────────────────────────

export interface BreachDirectorySource {
  name: string
  date: string | null
  count: number
}

export interface BreachDirectoryResult {
  found: boolean
  sources: BreachDirectorySource[]
  sha1_hash: string | null
}

export async function checkBreachDirectory(
  term: string,
  type: 'email' | 'domain' = 'email'
): Promise<BreachDirectoryResult> {
  return api.post<BreachDirectoryResult>('/hibp/breach-directory/check', { term, type })
}

// ── Jira ticketing ──────────────────────────────────────────────────────────

export interface JiraTicket {
  id: string
  finding_id: string
  provider: string
  ticket_key: string
  ticket_url: string
  created_at: string
}

export interface JiraStatus {
  configured: boolean
  enabled: boolean
  project_key: string | null
}

export const jiraApi = {
  status: () => api.get<JiraStatus>('/integrations/jira/status'),
  testConnection: () => api.post<{ ok: boolean; account: string }>('/integrations/jira/test'),
  createTicket: (findingId: string) =>
    api.post<JiraTicket & { created: boolean }>('/integrations/jira/tickets', { finding_id: findingId }),
  getTickets: (findingId: string) =>
    api.get<JiraTicket[]>(`/integrations/jira/tickets?finding_id=${encodeURIComponent(findingId)}`),
}

// ── SIEM export ─────────────────────────────────────────────────────────────

export const exportApi = {
  exportJsonl: (includeNoise = false) =>
    api.download(`/findings/export?format=jsonl&include_noise=${includeNoise}`, 'findings.jsonl'),
  exportCsv: (includeNoise = false) =>
    api.download(`/findings/export?format=csv&include_noise=${includeNoise}`, 'findings.csv'),
}

// ── IntelligenceX dark web search ──────────────────────────────────────────

export interface IntelRecord {
  name: string
  date: string
  bucket: string
  source: string
}

export interface IntelSearchResponse {
  results: IntelRecord[]
  total: number
  darkweb_count: number
}

export const intelApi = {
  search: (term: string, type: 'domain' | 'ip' | 'email' = 'domain') =>
    api.post<IntelSearchResponse>('/intel/search', { term, type }),
}

// ── Ransomware.live monitoring ──────────────────────────────────────────────

export interface RansomwareCheckResult {
  checked: number
  matches: number
  status: string
}

export interface RansomwareVictim {
  id: string
  title: string
  severity: string
  source: string
  raw_data: {
    source: string
    title: string
    group: string
    victim: string
    discovered_at: string
    leak_url: string
    description: string
    website: string
    country: string
  }
  first_seen_at: string
}

export const ransomwareApi = {
  checkNow: () =>
    api.post<RansomwareCheckResult>('/watchtower/ransomware-check'),
  listVictims: () =>
    api.get<RansomwareVictim[]>('/watchtower/ransomware-victims'),
}

// abuse.ch ThreatFox + URLhaus IOC feeds
export interface IOCCheckResult {
  term: string
  threatfox: {
    found: boolean
    threats: Array<{
      ioc_type: string
      threat_type: string
      malware: string | null
      confidence_level: number
      first_seen: string
      reference: string
      source: string
    }>
  }
  urlhaus: {
    found: boolean
    urls: Array<{
      url: string
      url_status: string
      threat: string
      date_added: string
      urlhaus_link: string
      source: string
    }>
  }
}

export interface IOCScanResult {
  checked: number
  threatfox_matches: number
  urlhaus_matches: number
  status: string
  org_id: string
}

export const threatFeedsApi = {
  checkIOC: (term: string) =>
    api.post<IOCCheckResult>('/threat-feeds/check-ioc', { term }),
  scanAssets: () =>
    api.post<IOCScanResult>('/threat-feeds/scan-assets'),
  listFindings: () =>
    api.get<any[]>('/threat-feeds/findings'),
}

// ── Incidents (Case Management) ──────────────────────────────────────────────

export type IncidentStatus = 'open' | 'in_progress' | 'resolved' | 'closed'
export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low'

export interface IncidentPerson {
  id: string
  name: string | null
  email: string | null
}

export interface IncidentSummary {
  id: string
  title: string
  description: string | null
  status: IncidentStatus
  severity: IncidentSeverity
  assignee_id: string | null
  assignee: IncidentPerson | null
  sla_deadline: string | null
  created_at: string
  closed_at: string | null
  updated_at: string
  finding_count: number
}

export interface IncidentFinding {
  id: string
  title: string | null
  severity: string | null
  status: string | null
  added_at: string
}

export interface IncidentNote {
  id: string
  incident_id: string
  author_id: string
  author: IncidentPerson | null
  body: string
  created_at: string
}

export interface IncidentDetail extends IncidentSummary {
  created_by: string | null
  created_by_user: IncidentPerson | null
  findings: IncidentFinding[]
  notes: IncidentNote[]
}

export interface IncidentListResponse {
  items: IncidentSummary[]
  page: number
  per_page: number
  total: number
}

export interface IncidentCreatePayload {
  title: string
  description?: string
  severity: IncidentSeverity
  assignee_id?: string | null
  sla_deadline?: string | null
  finding_ids?: string[]
}

export interface IncidentUpdatePayload {
  title?: string
  status?: IncidentStatus
  severity?: IncidentSeverity
  assignee_id?: string | null
  sla_deadline?: string | null
}

export const incidentsApi = {
  list: (params: { status?: string; severity?: string; assignee_id?: string } = {}) => {
    const qs = new URLSearchParams()
    if (params.status) qs.set('status', params.status)
    if (params.severity) qs.set('severity', params.severity)
    if (params.assignee_id) qs.set('assignee_id', params.assignee_id)
    const suffix = qs.toString() ? `?${qs}` : ''
    return api.get<IncidentListResponse>(`/incidents${suffix}`)
  },
  get: (id: string) => api.get<IncidentDetail>(`/incidents/${id}`),
  create: (body: IncidentCreatePayload) => api.post<IncidentSummary>('/incidents', body),
  update: (id: string, body: IncidentUpdatePayload) =>
    api.patch<IncidentSummary>(`/incidents/${id}`, body),
  close: (id: string) => api.delete<IncidentSummary>(`/incidents/${id}`),
  addFindings: (id: string, findingIds: string[]) =>
    api.post<{ linked: number }>(`/incidents/${id}/findings`, { finding_ids: findingIds }),
  removeFinding: (id: string, findingId: string) =>
    api.delete<void>(`/incidents/${id}/findings/${findingId}`),
  addNote: (id: string, body: string) =>
    api.post<IncidentNote>(`/incidents/${id}/notes`, { body }),
}
