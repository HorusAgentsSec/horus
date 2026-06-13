import { useEffect, useState } from 'react'
import { ShieldCheck, ShieldAlert } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { cn } from '../lib/utils'
import { ApiKeysSection } from '../components/ApiKeysSection'

const MASK = '••••••••'

interface Privacy {
  mode: string
  label: string
  data_leaves_perimeter: boolean
  description: string
  llm_enabled: boolean
  redaction_enabled: boolean
  llm_endpoint: string | null
}

function PrivacyCard() {
  const [p, setP] = useState<Privacy | null>(null)
  useEffect(() => {
    api.get<Privacy>('/privacy').then(setP).catch(() => setP(null))
  }, [])

  if (!p) return null
  const sovereign = !p.data_leaves_perimeter

  return (
    <section className="bg-surface border border-border rounded-lg p-6 space-y-4">
      <h2 className="text-sm font-medium text-white">Data privacy</h2>
      <div
        className={cn(
          'flex items-start gap-3 rounded-lg border p-4',
          sovereign
            ? 'border-mode-auto/30 bg-mode-auto/[0.06]'
            : 'border-severity-medium/30 bg-severity-medium/[0.06]',
        )}
      >
        {sovereign ? (
          <ShieldCheck className="w-5 h-5 text-mode-auto shrink-0 mt-0.5" />
        ) : (
          <ShieldAlert className="w-5 h-5 text-severity-medium shrink-0 mt-0.5" />
        )}
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-white">{p.label}</span>
            <span
              className={cn(
                'text-[10px] uppercase tracking-wide px-1.5 py-0.5 rounded border',
                sovereign
                  ? 'text-mode-auto border-mode-auto/40'
                  : 'text-severity-medium border-severity-medium/40',
              )}
            >
              {sovereign ? 'No data leaves' : 'Data leaves (protected)'}
            </span>
          </div>
          <p className="text-xs text-muted mt-1 leading-relaxed">{p.description}</p>
        </div>
      </div>
      <div className="grid grid-cols-3 gap-3 text-xs">
        <Stat label="AI agents" value={p.llm_enabled ? 'On' : 'Off (deterministic)'} />
        <Stat label="Redaction" value={p.redaction_enabled ? 'On' : 'Off'} />
        <Stat label="LLM endpoint" value={p.llm_endpoint ?? '— (none)'} mono />
      </div>
      <p className="text-xs text-muted">
        Configured via backend environment variables:{' '}
        <span className="font-mono">LLM_ENABLED</span>,{' '}
        <span className="font-mono">REDACTION_ENABLED</span>,{' '}
        <span className="font-mono">LLM_BASE_URL</span>.
      </p>
    </section>
  )
}

function Stat({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="bg-bg border border-border rounded p-3">
      <p className="text-muted uppercase text-[10px] tracking-wide mb-1">{label}</p>
      <p className={cn('text-white truncate', mono && 'font-mono')}>{value}</p>
    </div>
  )
}

export default function Settings() {
  const [shodanKey, setShodanKey] = useState('')
  const [keySet, setKeySet] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .get<{ shodan_api_key_set: boolean }>('/settings')
      .then((s) => {
        setKeySet(s.shodan_api_key_set)
        // Show the mask as a placeholder value when a key already exists; sending it back
        // unchanged is a no-op server-side, so editing-then-saving still works.
        if (s.shodan_api_key_set) setShodanKey(MASK)
      })
      .catch(() => {})
  }, [])

  const save = async () => {
    setSaving(true)
    setError(null)
    try {
      const res = await api.put<{ shodan_api_key_set: boolean }>('/settings', {
        shodan_api_key: shodanKey,
      })
      setKeySet(res.shodan_api_key_set)
      if (res.shodan_api_key_set) setShodanKey(MASK)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Failed to save settings'))
    } finally {
      setSaving(false)
    }
  }

  const field = 'bg-bg border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-accent w-full font-mono'

  return (
    <div className="max-w-2xl space-y-8">
      <h1 className="text-lg font-semibold">Settings</h1>

      <PrivacyCard />

      <section className="bg-surface border border-border rounded-lg p-6 space-y-4">
        <h2 className="text-sm font-medium text-white">Integrations</h2>
        <div>
          <label className="text-xs text-muted mb-1 block">
            Shodan API Key
            {keySet && <span className="ml-2 text-mode-auto">• configured</span>}
          </label>
          <input
            className={field}
            type="password"
            value={shodanKey}
            onFocus={() => { if (shodanKey === MASK) setShodanKey('') }}
            onChange={(e) => setShodanKey(e.target.value)}
            placeholder="••••••••••••••••"
          />
        </div>
        {error && <p className="text-xs text-severity-critical">{error}</p>}
        <button
          onClick={save}
          disabled={saving}
          className="text-sm bg-accent text-bg px-4 py-1.5 rounded hover:bg-accent/90 transition-colors disabled:opacity-50"
        >
          {saving ? 'Saving…' : saved ? 'Saved' : 'Save Changes'}
        </button>
      </section>

      <section className="bg-surface border border-border rounded-lg p-6 space-y-4">
        <h2 className="text-sm font-medium text-white">LLM Provider</h2>
        <div className="text-xs text-muted space-y-1">
          <p>Configured via environment variables on the backend.</p>
          <p className="font-mono bg-bg rounded px-2 py-1 border border-border">LLM_BASE_URL, LLM_API_KEY, LLM_DEFAULT_MODEL</p>
          <p className="mt-2">Per-agent overrides: <span className="font-mono">LLM_ANALYST_MODEL</span>, <span className="font-mono">LLM_THREAT_INTEL_MODEL</span>, etc.</p>
        </div>
      </section>

      <ApiKeysSection />
    </div>
  )
}
