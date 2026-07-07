import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, KeyRound } from 'lucide-react'
import { api } from '../lib/api'
import { supabase } from '../lib/supabase'
import { useAuth } from '../hooks/useAuth'

const MIN_LENGTH = 12

// Mirrors the backend policy (backend/core/password.py) for instant feedback.
function localPolicyError(pw: string): string | null {
  if (pw.length < MIN_LENGTH) return `At least ${MIN_LENGTH} characters.`
  if (!/[a-z]/.test(pw)) return 'Add a lowercase letter.'
  if (!/[A-Z]/.test(pw)) return 'Add an uppercase letter.'
  if (!/[0-9]/.test(pw)) return 'Add a digit.'
  return null
}

// `recovery` = reached via the forgot-password email link. The link opens a Supabase recovery
// session (detectSessionInUrl), so we set the password with GoTrue's updateUser instead of the
// backend endpoint: that endpoint requires a tenant profile and would 403 for a super-admin.
export default function ChangePassword({ recovery = false }: { recovery?: boolean }) {
  const navigate = useNavigate()
  const { mustChangePassword, refreshProfile, signOut } = useAuth()
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  // Recovery link handling: wait for the session the link establishes, or flag it dead.
  const [linkReady, setLinkReady] = useState(!recovery)
  const [linkError, setLinkError] = useState(false)

  useEffect(() => {
    if (!recovery) return
    let settled = false
    const markReady = () => { settled = true; setLinkReady(true) }
    void supabase.auth.getSession().then(({ data }) => { if (data.session) markReady() })
    const { data: listener } = supabase.auth.onAuthStateChange((event, session) => {
      if (event === 'PASSWORD_RECOVERY' || (event === 'SIGNED_IN' && session)) markReady()
    })
    const t = setTimeout(() => { if (!settled) setLinkError(true) }, 4000)
    return () => { listener.subscription.unsubscribe(); clearTimeout(t) }
  }, [recovery])

  const policyError = password ? localPolicyError(password) : null
  const mismatch = confirm.length > 0 && password !== confirm
  const canSubmit = !policyError && !mismatch && confirm.length > 0 && !saving

  const submit = async () => {
    setError(null)
    if (password !== confirm) { setError('Passwords do not match.'); return }
    const local = localPolicyError(password)
    if (local) { setError(local); return }

    setSaving(true)
    try {
      if (recovery) {
        const { error: upErr } = await supabase.auth.updateUser({ password })
        if (upErr) throw new Error(upErr.message)
      } else {
        await api.post('/account/change-password', { new_password: password })
        await refreshProfile()
      }
      navigate('/dashboard', { replace: true })
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to change password')
    } finally {
      setSaving(false)
    }
  }

  const field = 'w-full bg-bg border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-accent'

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2 justify-center mb-8">
          <Shield className="text-accent w-6 h-6" />
          <span className="text-xl font-semibold text-white">Horus</span>
        </div>
        <div className="bg-surface border border-border rounded-xl p-6 space-y-5">
          <div className="flex items-center gap-2 text-white">
            <KeyRound className="w-4 h-4 text-accent" />
            <h1 className="text-sm font-semibold">Set a new password</h1>
          </div>
          {recovery && (
            <p className="text-xs text-muted">
              Choose a new password for your account.
            </p>
          )}
          {!recovery && mustChangePassword && (
            <p className="text-xs text-muted">
              Your account was created with a temporary password. Choose a new one to continue.
            </p>
          )}

          {recovery && linkError && !linkReady ? (
            <div className="space-y-3">
              <p className="text-xs text-severity-critical">
                This reset link is invalid or has expired.
              </p>
              <button
                onClick={() => navigate('/login', { replace: true })}
                className="w-full bg-accent text-bg text-sm font-medium px-4 py-2 rounded hover:bg-accent/90 transition-colors"
              >
                Back to sign in
              </button>
            </div>
          ) : recovery && !linkReady ? (
            <p className="text-xs text-muted">Verifying reset link…</p>
          ) : (
          <>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-muted mb-1 block">New password</label>
              <input
                className={field}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
              />
              {policyError && <p className="text-xs text-severity-high mt-1">{policyError}</p>}
            </div>
            <div>
              <label className="text-xs text-muted mb-1 block">Confirm password</label>
              <input
                className={field}
                type="password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                autoComplete="new-password"
              />
              {mismatch && <p className="text-xs text-severity-high mt-1">Passwords do not match.</p>}
            </div>
          </div>

          {error && <p className="text-xs text-severity-critical">{error}</p>}

          <button
            onClick={submit}
            disabled={!canSubmit}
            className="w-full bg-accent text-bg text-sm font-medium px-4 py-2 rounded hover:bg-accent/90 transition-colors disabled:opacity-50"
          >
            {saving ? 'Saving…' : 'Set password'}
          </button>

          {!recovery && (
            <button
              onClick={() => signOut()}
              className="w-full text-xs text-muted hover:text-white transition-colors"
            >
              Sign out
            </button>
          )}
          </>
          )}
        </div>
      </div>
    </div>
  )
}
