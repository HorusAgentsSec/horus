import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, KeyRound } from 'lucide-react'
import { api } from '../lib/api'
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

export default function ChangePassword() {
  const navigate = useNavigate()
  const { mustChangePassword, refreshProfile, signOut } = useAuth()
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

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
      await api.post('/account/change-password', { new_password: password })
      await refreshProfile()
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
          {mustChangePassword && (
            <p className="text-xs text-muted">
              Your account was created with a temporary password. Choose a new one to continue.
            </p>
          )}

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

          <button
            onClick={() => signOut()}
            className="w-full text-xs text-muted hover:text-white transition-colors"
          >
            Sign out
          </button>
        </div>
      </div>
    </div>
  )
}
