import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Cloud, Play, Plus, RefreshCw } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { cn } from '../lib/utils'
import { Modal } from '../components/Modal'

interface Integration {
  id: string
  type: string
  enabled: boolean
  config: { region?: string; label?: string; project_id?: string }
}

interface AuditJob {
  id: string
  status: string
  started_at: string
  detail: { account_id?: string; findings?: number; by_severity?: Record<string, number> } | null
}

const STATUS_COLOR: Record<string, string> = {
  completed: 'text-mode-auto',
  running: 'text-accent',
  failed: 'text-severity-critical',
}

export default function CloudSecurity() {
  const [accounts, setAccounts] = useState<Integration[]>([])
  const [audits, setAudits] = useState<AuditJob[]>([])
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [provider, setProvider] = useState<'aws' | 'gcp'>('aws')
  const [form, setForm] = useState({
    label: '', access_key_id: '', secret_access_key: '', region: 'us-east-1',
    project_id: '', service_account_json: '',
  })

  const load = useCallback(async () => {
    try {
      const [ints, jobs] = await Promise.all([
        api.get<Integration[]>('/integrations'),
        api.get<AuditJob[]>('/cloud/audits'),
      ])
      setAccounts(ints.filter((i) => i.type === 'aws' || i.type === 'gcp'))
      setAudits(jobs)
      setError(null)
    } catch (e: unknown) {
      setError(friendlyErrorMessage(e, 'Failed to load cloud security'))
    }
  }, [])

  useEffect(() => {
    load()
    // Poll while an audit is running so findings counts refresh as the job completes.
    const interval = window.setInterval(load, 4000)
    return () => window.clearInterval(interval)
  }, [load])

  const addAccount = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy('add')
    try {
      const config = provider === 'aws'
        ? {
            label: form.label || undefined,
            access_key_id: form.access_key_id,
            secret_access_key: form.secret_access_key,
            region: form.region,
          }
        : {
            label: form.label || undefined,
            project_id: form.project_id,
            service_account_json: form.service_account_json,
          }
      await api.post('/integrations', { type: provider, enabled: true, config })
      setShowForm(false)
      setForm({ label: '', access_key_id: '', secret_access_key: '', region: 'us-east-1',
                project_id: '', service_account_json: '' })
      await load()
    } catch (e: unknown) {
      setError(friendlyErrorMessage(e, 'Failed to add account'))
    } finally {
      setBusy(null)
    }
  }

  const runAudit = async (id: string, type: string) => {
    setBusy(id)
    try {
      await api.post(`/cloud/${type}/${id}/audit`)
      await load()
    } catch (e: unknown) {
      setError(friendlyErrorMessage(e, 'Failed to start audit'))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="max-w-3xl space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2">
            <Cloud className="w-5 h-5 text-accent" /> Cloud Security
          </h1>
          <p className="text-sm text-muted mt-1">
            Read-only AWS &amp; GCP posture (CSPM) and CI/CD checks. Findings appear in the normal Findings list.
          </p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-2 border border-border px-3 py-2 text-xs text-muted hover:text-white"
        >
          <Plus className="w-4 h-4" /> Connect account
        </button>
      </div>

      {error && <p className="text-sm text-severity-critical">{error}</p>}

      <Modal open={showForm} onClose={() => setShowForm(false)} title="Connect cloud account" className="max-w-lg">
        <form onSubmit={addAccount} className="space-y-3">
          <div className="flex gap-2">
            {(['aws', 'gcp'] as const).map((p) => (
              <button key={p} type="button" onClick={() => setProvider(p)}
                className={cn('px-3 py-1.5 text-xs rounded border uppercase',
                  provider === p ? 'border-accent text-accent' : 'border-border text-muted hover:text-white')}>
                {p}
              </button>
            ))}
          </div>
          {provider === 'aws' ? (
            <>
              <p className="text-xs text-muted">
                Use a dedicated <strong>read-only</strong> IAM user (e.g. the AWS managed
                <code className="mx-1">SecurityAudit</code> policy). Credentials are stored encrypted and never returned.
              </p>
              <div className="grid grid-cols-2 gap-3">
                <input className="bg-bg border border-border rounded px-3 py-2 text-sm" placeholder="Label (optional)"
                  value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} />
                <input className="bg-bg border border-border rounded px-3 py-2 text-sm" placeholder="Region"
                  value={form.region} onChange={(e) => setForm({ ...form, region: e.target.value })} />
                <input className="bg-bg border border-border rounded px-3 py-2 text-sm" placeholder="Access key ID" required
                  value={form.access_key_id} onChange={(e) => setForm({ ...form, access_key_id: e.target.value })} />
                <input className="bg-bg border border-border rounded px-3 py-2 text-sm" placeholder="Secret access key" type="password" required
                  value={form.secret_access_key} onChange={(e) => setForm({ ...form, secret_access_key: e.target.value })} />
              </div>
            </>
          ) : (
            <>
              <p className="text-xs text-muted">
                Use a <strong>read-only</strong> service account (e.g. roles <code className="mx-1">Viewer</code>
                + <code className="mx-1">Security Reviewer</code>). Paste its JSON key. Stored encrypted, never returned.
              </p>
              <div className="grid grid-cols-2 gap-3">
                <input className="bg-bg border border-border rounded px-3 py-2 text-sm" placeholder="Label (optional)"
                  value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} />
                <input className="bg-bg border border-border rounded px-3 py-2 text-sm" placeholder="Project ID" required
                  value={form.project_id} onChange={(e) => setForm({ ...form, project_id: e.target.value })} />
              </div>
              <textarea className="w-full bg-bg border border-border rounded px-3 py-2 text-sm font-mono h-28"
                placeholder='Service account JSON key {"type":"service_account", ...}' required
                value={form.service_account_json} onChange={(e) => setForm({ ...form, service_account_json: e.target.value })} />
            </>
          )}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={() => setShowForm(false)} className="text-sm text-muted hover:text-white px-3 py-2">
              Cancel
            </button>
            <button disabled={busy === 'add'} className="bg-accent text-bg px-4 py-2 rounded text-sm font-medium disabled:opacity-50">
              {busy === 'add' ? 'Saving…' : 'Save account'}
            </button>
          </div>
        </form>
      </Modal>

      <div className="bg-surface border border-border rounded-lg p-5">
        <h2 className="text-sm font-medium text-muted uppercase mb-4">Connected accounts</h2>
        {accounts.length === 0 ? (
          <p className="text-sm text-muted">No AWS accounts connected yet.</p>
        ) : (
          <ul className="space-y-2">
            {accounts.map((a) => (
              <li key={a.id} className="flex items-center gap-3 border border-white/5 rounded-lg px-3 py-2">
                <span className="shrink-0 rounded border border-border px-1.5 py-0.5 text-[10px] uppercase text-muted">{a.type}</span>
                <span className="flex-1 text-sm text-white/85">
                  {a.config.label || `${a.type.toUpperCase()} account`}
                  <span className="text-muted"> · {a.type === 'aws' ? (a.config.region || 'us-east-1') : (a.config.project_id || 'project')}</span>
                </span>
                <button onClick={() => runAudit(a.id, a.type)} disabled={busy === a.id}
                  className="flex items-center gap-1.5 text-xs border border-border px-2.5 py-1.5 rounded text-muted hover:text-white disabled:opacity-50">
                  {busy === a.id ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                  Run audit
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="bg-surface border border-border rounded-lg p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-medium text-muted uppercase">Recent audits</h2>
          <Link to="/findings" className="text-xs text-accent hover:underline">View all findings →</Link>
        </div>
        {audits.length === 0 ? (
          <p className="text-sm text-muted">No audits run yet.</p>
        ) : (
          <ul className="space-y-1.5 text-sm">
            {audits.map((j) => (
              <li key={j.id} className="flex items-center gap-3 border border-white/5 rounded-lg px-3 py-2">
                <span className={cn('text-xs capitalize w-20 shrink-0', STATUS_COLOR[j.status] ?? 'text-muted')}>{j.status}</span>
                <span className="flex-1 truncate text-white/80">{j.detail?.account_id ?? '—'}</span>
                {j.detail?.findings != null && (
                  <span className="text-xs text-muted shrink-0">{j.detail.findings} findings</span>
                )}
                <span className="text-xs text-muted shrink-0">{new Date(j.started_at).toLocaleString()}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
