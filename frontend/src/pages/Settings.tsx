import { useEffect, useRef, useState } from 'react'
import { ShieldCheck, ShieldAlert, TriangleAlert, CreditCard } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { cn } from '../lib/utils'
import { useUser } from '../contexts/UserContext'
import { ApiKeysSection } from '../components/ApiKeysSection'

function BillingCard() {
  const { can } = useUser()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Billing is the org admin's concern; the backend also enforces the admin role.
  if (!can('admin')) return null

  async function openPortal() {
    setLoading(true)
    setError(null)
    try {
      const { url } = await api.post<{ url: string }>('/billing/portal')
      window.location.href = url
    } catch (e) {
      setError(friendlyErrorMessage(e))
      setLoading(false)
    }
  }

  return (
    <section className="bg-surface border border-border rounded-lg p-6 space-y-4">
      <h2 className="text-sm font-medium text-white">Billing</h2>
      <p className="text-xs text-muted leading-relaxed">
        Manage your subscription in the secure Stripe portal: change the number of seats,
        update your payment method, view invoices, or cancel. Seat changes are prorated
        automatically, so lowering seats reduces your next invoice.
      </p>
      {error && <p className="text-xs text-severity-critical">{error}</p>}
      <button
        onClick={openPortal}
        disabled={loading}
        className="inline-flex items-center gap-2 text-sm bg-accent text-bg px-4 py-1.5 rounded hover:bg-accent/90 transition-colors disabled:opacity-50"
      >
        <CreditCard className="w-4 h-4" />
        {loading ? 'Opening…' : 'Manage billing'}
      </button>
    </section>
  )
}

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

function TokenLimitsSection() {
  const [limits, setLimits] = useState({ daily: '', weekly: '', monthly: '' })
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    api.get<any>('/settings').then(s => setLimits({
      daily:   s.token_limit_daily   ? String(s.token_limit_daily)   : '',
      weekly:  s.token_limit_weekly  ? String(s.token_limit_weekly)  : '',
      monthly: s.token_limit_monthly ? String(s.token_limit_monthly) : '',
    })).catch(() => {})
  }, [])

  const save = async () => {
    setSaving(true)
    try {
      await api.put('/settings', {
        token_limit_daily:   limits.daily   ? parseInt(limits.daily)   : 0,
        token_limit_weekly:  limits.weekly  ? parseInt(limits.weekly)  : 0,
        token_limit_monthly: limits.monthly ? parseInt(limits.monthly) : 0,
      })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch { /* ignore */ } finally { setSaving(false) }
  }

  const field = 'bg-bg border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-accent w-full font-mono'

  return (
    <section className="bg-surface border border-border rounded-lg p-6 space-y-4">
      <div>
        <h2 className="text-sm font-medium text-white">Token limits</h2>
        <p className="text-xs text-muted mt-1">
          AI agents are paused and you receive an alert when limits are reached. 80% threshold sends an advance warning. Leave blank for no limit.
        </p>
      </div>
      <div className="grid grid-cols-3 gap-4">
        {(['daily', 'weekly', 'monthly'] as const).map(period => (
          <div key={period}>
            <label className="text-xs text-muted mb-1 block capitalize">{period}</label>
            <input
              className={field}
              type="number"
              min="1"
              placeholder="No limit"
              value={limits[period]}
              onChange={e => setLimits(l => ({ ...l, [period]: e.target.value }))}
            />
          </div>
        ))}
      </div>
      <button
        onClick={save}
        disabled={saving}
        className="text-sm bg-accent text-bg px-4 py-1.5 rounded hover:bg-accent/90 transition-colors disabled:opacity-50"
      >
        {saving ? 'Saving…' : saved ? 'Saved ✓' : 'Save Limits'}
      </button>
    </section>
  )
}

function DangerZone() {
  const [open, setOpen] = useState(false)
  const [confirm, setConfirm] = useState('')
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const CONFIRM_WORD = 'DELETE'

  const handleDelete = async () => {
    if (confirm !== CONFIRM_WORD) return
    setDeleting(true)
    setError(null)
    try {
      await api.delete('/settings/organization')
      // Force full logout — org no longer exists
      window.location.href = '/login'
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Failed to delete organization'))
      setDeleting(false)
    }
  }

  return (
    <section className="bg-surface border border-severity-critical/30 rounded-lg p-6 space-y-4">
      <div className="flex items-center gap-2">
        <TriangleAlert className="w-4 h-4 text-severity-critical" />
        <h2 className="text-sm font-medium text-severity-critical">Danger zone</h2>
      </div>

      {!open ? (
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-white">Delete organization</p>
            <p className="text-xs text-muted mt-0.5">
              Permanently delete this organization and all its data. Cannot be undone.
            </p>
          </div>
          <button
            onClick={() => { setOpen(true); setTimeout(() => inputRef.current?.focus(), 50) }}
            className="text-sm border border-severity-critical/50 text-severity-critical px-3 py-1.5 rounded hover:bg-severity-critical/10 transition-colors shrink-0 ml-4"
          >
            Delete organization
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-white">
            This will permanently delete all data including assets, findings, scans, agents, and users.
            <strong className="text-severity-critical"> This cannot be undone.</strong>
          </p>
          <div>
            <label className="text-xs text-muted mb-1 block">
              Type <span className="font-mono text-white">{CONFIRM_WORD}</span> to confirm
            </label>
            <input
              ref={inputRef}
              className="bg-bg border border-severity-critical/40 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-severity-critical w-full font-mono"
              value={confirm}
              onChange={e => setConfirm(e.target.value.toUpperCase())}
              placeholder={CONFIRM_WORD}
            />
          </div>
          {error && <p className="text-xs text-severity-critical">{error}</p>}
          <div className="flex gap-2">
            <button
              onClick={handleDelete}
              disabled={confirm !== CONFIRM_WORD || deleting}
              className="text-sm bg-severity-critical text-white px-4 py-1.5 rounded hover:bg-severity-critical/80 transition-colors disabled:opacity-40"
            >
              {deleting ? 'Deleting…' : 'Delete permanently'}
            </button>
            <button
              onClick={() => { setOpen(false); setConfirm(''); setError(null) }}
              className="text-sm border border-border text-muted px-4 py-1.5 rounded hover:text-white transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </section>
  )
}

function IntegrationsSection() {
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
  )
}

function LlmProviderCard() {
  return (
    <section className="bg-surface border border-border rounded-lg p-6 space-y-4">
      <h2 className="text-sm font-medium text-white">LLM Provider</h2>
      <div className="text-xs text-muted space-y-1">
        <p>Configured via environment variables on the backend.</p>
        <p className="font-mono bg-bg rounded px-2 py-1 border border-border">LLM_BASE_URL, LLM_API_KEY, LLM_DEFAULT_MODEL</p>
        <p className="mt-2">Per-agent overrides: <span className="font-mono">LLM_ANALYST_MODEL</span>, <span className="font-mono">LLM_THREAT_INTEL_MODEL</span>, etc.</p>
      </div>
    </section>
  )
}

const TABS = [
  { id: 'general',      label: 'General' },
  { id: 'billing',      label: 'Billing' },
  { id: 'llm',          label: 'LLM & limits' },
  { id: 'integrations', label: 'Integrations' },
  { id: 'api-keys',     label: 'API keys' },
  { id: 'danger',       label: 'Danger zone' },
] as const
type TabId = (typeof TABS)[number]['id']

export default function Settings() {
  const [tab, setTab] = useState<TabId>('general')

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-lg font-semibold">Settings</h1>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border flex-wrap">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              'px-4 py-2 text-sm border-b-2 -mb-px transition-colors whitespace-nowrap',
              tab === t.id
                ? t.id === 'danger'
                  ? 'border-severity-critical text-severity-critical'
                  : 'border-accent text-accent'
                : 'border-transparent text-muted hover:text-white',
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="space-y-8">
        {tab === 'general'      && <PrivacyCard />}
        {tab === 'billing'      && <BillingCard />}
        {tab === 'llm'          && <><LlmProviderCard /><TokenLimitsSection /></>}
        {tab === 'integrations' && <IntegrationsSection />}
        {tab === 'api-keys'     && <ApiKeysSection />}
        {tab === 'danger'       && <DangerZone />}
      </div>
    </div>
  )
}
