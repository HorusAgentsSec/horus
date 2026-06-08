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
