import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Building2 } from 'lucide-react'
import { api } from '../lib/api'
import { useAuth } from '../hooks/useAuth'

const MAX_ORG_NAME = 100

export default function Onboarding() {
  const navigate = useNavigate()
  const { refreshProfile, signOut } = useAuth()
  const [name, setName] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  const trimmed = name.trim()
  const canSubmit = trimmed.length > 0 && trimmed.length <= MAX_ORG_NAME && !saving

  const submit = async () => {
    setError(null)
    setSaving(true)
    try {
      await api.post('/onboarding', { org_name: trimmed })
      await refreshProfile()
      navigate('/dashboard', { replace: true })
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to create organization')
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
            <Building2 className="w-4 h-4 text-accent" />
            <h1 className="text-sm font-semibold">Create your organization</h1>
          </div>
          <p className="text-xs text-muted">
            Welcome! Set up your workspace to get started — you'll be its admin and can invite
            your team afterwards.
          </p>

          <div>
            <label className="text-xs text-muted mb-1 block">Organization name</label>
            <input
              className={field}
              value={name}
              maxLength={MAX_ORG_NAME}
              onChange={(e) => setName(e.target.value)}
              placeholder="Acme Security"
              onKeyDown={(e) => { if (e.key === 'Enter' && canSubmit) submit() }}
              autoFocus
            />
          </div>

          {error && <p className="text-xs text-severity-critical">{error}</p>}

          <button
            onClick={submit}
            disabled={!canSubmit}
            className="w-full bg-accent text-bg text-sm font-medium px-4 py-2 rounded hover:bg-accent/90 transition-colors disabled:opacity-50"
          >
            {saving ? 'Creating…' : 'Create organization'}
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
