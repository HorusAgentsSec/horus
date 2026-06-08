import { useEffect, useState } from 'react'
import { Bell, Slack, Mail, Plus, Trash2, Send, X, FileText } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { useRole } from '../hooks/useRole'
import { cn } from '../lib/utils'

type IntegrationType = 'slack' | 'email'

interface Integration {
  id: string
  type: IntegrationType
  config: Record<string, any>
  enabled: boolean
  created_at: string
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const

const input =
  'bg-bg border border-border text-sm text-white rounded px-3 py-1.5 w-full focus:outline-none focus:border-accent placeholder:text-muted/60'
const label = 'text-xs text-muted mb-1 block'

export default function Integrations() {
  const { can } = useRole()
  const [items, setItems] = useState<Integration[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [status, setStatus] = useState<{ id: string; msg: string; ok: boolean } | null>(null)

  const load = () => {
    setLoading(true)
    api.get<Integration[]>('/integrations').then(setItems).finally(() => setLoading(false))
  }
  useEffect(load, [])

  if (!can('admin')) {
    return <div className="text-sm text-muted">Integrations are restricted to administrators.</div>
  }

  const toggle = async (it: Integration) => {
    await api.patch(`/integrations/${it.id}`, { enabled: !it.enabled })
    load()
  }

  const toggleBoardReport = async (it: Integration) => {
    await api.patch(`/integrations/${it.id}/board-report`, { enabled: !it.config.posture_report })
    load()
  }

  const remove = async (id: string) => {
    if (!confirm('Delete this integration?')) return
    await api.delete(`/integrations/${id}`)
    load()
  }

  const test = async (id: string) => {
    setStatus({ id, msg: 'Sending…', ok: true })
    try {
      await api.post(`/integrations/${id}/test`)
      setStatus({ id, msg: 'Test sent ✓', ok: true })
    } catch (e) {
      setStatus({ id, msg: friendlyErrorMessage(e, 'Test failed'), ok: false })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bell className="w-5 h-5 text-accent" />
          <h1 className="text-lg font-semibold">Integrations</h1>
        </div>
        <button
          onClick={() => setShowForm((s) => !s)}
          className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-1.5 rounded-md hover:bg-accent/20 transition-colors"
        >
          {showForm ? <X className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
          {showForm ? 'Cancel' : 'Add integration'}
        </button>
      </div>

      <p className="text-sm text-muted -mt-2">
        Get notified when a scan finishes. By default alerts fire only for high/critical findings or
        actively-exploited (CISA KEV) CVEs.
      </p>

      {showForm && <AddForm onCreated={() => { setShowForm(false); load() }} />}

      <div className="space-y-3">
        {loading ? (
          <div className="text-xs text-muted py-8 text-center">Loading…</div>
        ) : !items.length ? (
          <div className="text-xs text-muted py-8 text-center">
            No integrations yet. Add Slack or email to start getting alerts.
          </div>
        ) : (
          items.map((it) => (
            <div
              key={it.id}
              className="bg-surface border border-border rounded-lg p-4 flex items-center justify-between gap-4"
            >
              <div className="flex items-center gap-3 min-w-0">
                {it.type === 'slack' ? (
                  <Slack className="w-5 h-5 text-accent shrink-0" />
                ) : (
                  <Mail className="w-5 h-5 text-accent shrink-0" />
                )}
                <div className="min-w-0">
                  <p className="text-white capitalize">{it.type}</p>
                  <p className="text-xs text-muted truncate">
                    {it.type === 'slack'
                      ? it.config.webhook_url || 'webhook'
                      : (it.config.to || []).join(', ') || 'no recipients'}
                    {it.config.min_severity && ` · ≥ ${it.config.min_severity}`}
                  </p>
                  {status?.id === it.id && (
                    <p className={cn('text-xs mt-0.5', status.ok ? 'text-mode-auto' : 'text-severity-high')}>
                      {status.msg}
                    </p>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-3 shrink-0">
                {it.type === 'email' && (
                  <button
                    onClick={() => toggleBoardReport(it)}
                    title="Email a board-ready posture PDF on the 1st of each month"
                    className={cn(
                      'flex items-center gap-1 text-xs px-2 py-1 rounded transition-colors',
                      it.config.posture_report
                        ? 'bg-accent/10 text-accent'
                        : 'text-muted hover:text-white',
                    )}
                  >
                    <FileText className="w-3.5 h-3.5" /> Board report
                  </button>
                )}
                <button
                  onClick={() => test(it.id)}
                  className="flex items-center gap-1 text-xs text-muted hover:text-white transition-colors"
                >
                  <Send className="w-3.5 h-3.5" /> Test
                </button>
                <button
                  onClick={() => toggle(it)}
                  className={cn(
                    'text-xs px-2 py-1 rounded transition-colors',
                    it.enabled ? 'bg-mode-auto/10 text-mode-auto' : 'bg-white/5 text-muted',
                  )}
                >
                  {it.enabled ? 'Enabled' : 'Disabled'}
                </button>
                <button
                  onClick={() => remove(it.id)}
                  className="text-muted hover:text-severity-critical transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

function AddForm({ onCreated }: { onCreated: () => void }) {
  const [type, setType] = useState<IntegrationType>('slack')
  const [minSeverity, setMinSeverity] = useState('high')
  const [webhookUrl, setWebhookUrl] = useState('')
  const [to, setTo] = useState('')
  const [smtp, setSmtp] = useState({ smtp_host: '', smtp_port: '', smtp_user: '', smtp_password: '', from_addr: '' })
  const [boardReport, setBoardReport] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const submit = async () => {
    setError('')
    const config: Record<string, any> = { min_severity: minSeverity }
    if (type === 'slack') {
      if (!webhookUrl.trim()) return setError('Webhook URL is required')
      config.webhook_url = webhookUrl.trim()
    } else {
      const recipients = to.split(',').map((s) => s.trim()).filter(Boolean)
      if (!recipients.length) return setError('At least one recipient is required')
      config.to = recipients
      for (const [k, v] of Object.entries(smtp)) {
        if (v.trim()) config[k] = k === 'smtp_port' ? Number(v) : v.trim()
      }
      if (boardReport) config.posture_report = true
    }
    setSaving(true)
    try {
      await api.post('/integrations', { type, config, enabled: true })
      onCreated()
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Could not create integration'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="bg-surface border border-border rounded-lg p-4 space-y-4">
      <div className="flex gap-2">
        {(['slack', 'email'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setType(t)}
            className={cn(
              'flex items-center gap-1.5 text-sm px-3 py-1.5 rounded-md capitalize transition-colors',
              type === t ? 'bg-accent/10 text-accent' : 'text-muted hover:text-white',
            )}
          >
            {t === 'slack' ? <Slack className="w-4 h-4" /> : <Mail className="w-4 h-4" />}
            {t}
          </button>
        ))}
      </div>

      {type === 'slack' ? (
        <div>
          <label className={label}>Slack Incoming Webhook URL</label>
          <input
            className={input}
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://hooks.slack.com/services/…"
          />
        </div>
      ) : (
        <div className="space-y-3">
          <div>
            <label className={label}>Recipients (comma-separated)</label>
            <input
              className={input}
              value={to}
              onChange={(e) => setTo(e.target.value)}
              placeholder="security@company.com, oncall@company.com"
            />
          </div>
          <details className="text-sm">
            <summary className="text-xs text-muted cursor-pointer hover:text-white">
              SMTP server (optional — uses server defaults if blank)
            </summary>
            <div className="grid grid-cols-2 gap-3 mt-3">
              <input className={input} placeholder="smtp host" value={smtp.smtp_host} onChange={(e) => setSmtp({ ...smtp, smtp_host: e.target.value })} />
              <input className={input} placeholder="port (587)" value={smtp.smtp_port} onChange={(e) => setSmtp({ ...smtp, smtp_port: e.target.value })} />
              <input className={input} placeholder="username" value={smtp.smtp_user} onChange={(e) => setSmtp({ ...smtp, smtp_user: e.target.value })} />
              <input className={input} type="password" placeholder="password" value={smtp.smtp_password} onChange={(e) => setSmtp({ ...smtp, smtp_password: e.target.value })} />
              <input className={cn(input, 'col-span-2')} placeholder="from address" value={smtp.from_addr} onChange={(e) => setSmtp({ ...smtp, from_addr: e.target.value })} />
            </div>
          </details>
          <label className="flex items-start gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={boardReport}
              onChange={(e) => setBoardReport(e.target.checked)}
              className="mt-0.5 accent-accent"
            />
            <span className="text-xs text-muted">
              <span className="text-white">Email a monthly board report</span> — a board-ready
              posture PDF (risk trend + severity breakdown) on the 1st of each month.
            </span>
          </label>
        </div>
      )}

      <div className="flex items-center gap-3">
        <div className="flex-1">
          <label className={label}>Notify when severity is at least</label>
          <select className={input} value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s} className="capitalize">{s}</option>
            ))}
          </select>
        </div>
        <button
          onClick={submit}
          disabled={saving}
          className="self-end bg-accent text-bg font-medium text-sm px-4 py-1.5 rounded-md hover:bg-accent/90 disabled:opacity-50 transition-colors"
        >
          {saving ? 'Saving…' : 'Save'}
        </button>
      </div>

      {error && <p className="text-xs text-severity-high">{error}</p>}
    </div>
  )
}
