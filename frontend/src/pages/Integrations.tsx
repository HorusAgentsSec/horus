import { useEffect, useState } from 'react'
import { Bell, Slack, Mail, Plus, Trash2, Send, FileText, AlertTriangle, Ticket, Webhook, MessageSquare } from 'lucide-react'
import { api, jiraApi, friendlyErrorMessage } from '../lib/api'
import { useRole } from '../hooks/useRole'
import { cn } from '../lib/utils'
import { Modal } from '../components/Modal'
import { Select } from '../components/ui/Select'
import { useConfirm } from '../components/ui/ConfirmProvider'

type IntegrationType = 'slack' | 'teams' | 'email' | 'pagerduty' | 'opsgenie' | 'jira' | 'webhook'

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
  const confirm = useConfirm()
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
    if (!(await confirm({ message: 'Delete this integration?', danger: true, confirmLabel: 'Delete' }))) return
    await api.delete(`/integrations/${id}`)
    load()
  }

  const test = async (it: Integration) => {
    setStatus({ id: it.id, msg: it.type === 'jira' ? 'Testing connection…' : 'Sending…', ok: true })
    try {
      if (it.type === 'jira') {
        const res = await jiraApi.testConnection()
        setStatus({ id: it.id, msg: `Connected as ${res.account} ✓`, ok: true })
      } else {
        await api.post(`/integrations/${it.id}/test`)
        setStatus({ id: it.id, msg: 'Test sent ✓', ok: true })
      }
    } catch (e) {
      setStatus({ id: it.id, msg: friendlyErrorMessage(e, 'Test failed'), ok: false })
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
          onClick={() => setShowForm(true)}
          className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-1.5 rounded-md hover:bg-accent/20 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add integration
        </button>
      </div>

      <p className="text-sm text-muted -mt-2">
        Get notified when a scan finishes. By default alerts fire only for high/critical findings or
        actively-exploited (CISA KEV) CVEs.
      </p>

      {showForm && (
        <AddForm onClose={() => setShowForm(false)} onCreated={() => { setShowForm(false); load() }} />
      )}

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
                ) : it.type === 'teams' ? (
                  <MessageSquare className="w-5 h-5 text-accent shrink-0" />
                ) : it.type === 'email' ? (
                  <Mail className="w-5 h-5 text-accent shrink-0" />
                ) : it.type === 'jira' ? (
                  <Ticket className="w-5 h-5 text-accent shrink-0" />
                ) : it.type === 'webhook' ? (
                  <Webhook className="w-5 h-5 text-accent shrink-0" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-accent shrink-0" />
                )}
                <div className="min-w-0">
                  <p className="text-white capitalize">{it.type === 'pagerduty' ? 'PagerDuty' : it.type === 'opsgenie' ? 'OpsGenie' : it.type === 'jira' ? 'Jira' : it.type === 'webhook' ? 'Outgoing webhook' : it.type === 'teams' ? 'Microsoft Teams' : it.type}</p>
                  <p className="text-xs text-muted truncate">
                    {it.type === 'slack' || it.type === 'teams'
                      ? it.config.webhook_url || 'webhook'
                      : it.type === 'email'
                      ? (it.config.to || []).join(', ') || 'no recipients'
                      : it.type === 'jira'
                      ? `${it.config.base_url || 'no URL'} · project ${it.config.project_key || '?'} · tickets from findings`
                      : it.type === 'webhook'
                      ? `${it.config.url || 'no URL'} · fires on new critical findings · HMAC-signed`
                      : it.type === 'pagerduty'
                      ? 'Events API v2 · SSVC-Act triggers P1'
                      : 'Alerts API · SSVC-Act triggers P1'}
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
                  onClick={() => test(it)}
                  className="flex items-center gap-1 text-xs text-muted hover:text-white transition-colors"
                >
                  <Send className="w-3.5 h-3.5" /> {it.type === 'jira' ? 'Test connection' : 'Test'}
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

function AddForm({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [type, setType] = useState<IntegrationType>('slack')
  const [minSeverity, setMinSeverity] = useState('high')
  const [webhookUrl, setWebhookUrl] = useState('')
  const [to, setTo] = useState('')
  const [smtp, setSmtp] = useState({ smtp_host: '', smtp_port: '', smtp_user: '', smtp_password: '', from_addr: '' })
  const [boardReport, setBoardReport] = useState(false)
  const [pdKey, setPdKey] = useState('')
  const [ogKey, setOgKey] = useState('')
  const [jira, setJira] = useState({ base_url: '', user_email: '', api_token: '', project_key: '' })
  const [hook, setHook] = useState({ url: '', secret: '' })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const submit = async () => {
    setError('')
    const config: Record<string, any> = {}
    if (type === 'slack' || type === 'teams') {
      if (!webhookUrl.trim()) return setError('Webhook URL is required')
      config.webhook_url = webhookUrl.trim()
      config.min_severity = minSeverity
    } else if (type === 'email') {
      const recipients = to.split(',').map((s) => s.trim()).filter(Boolean)
      if (!recipients.length) return setError('At least one recipient is required')
      config.to = recipients
      config.min_severity = minSeverity
      for (const [k, v] of Object.entries(smtp)) {
        if (v.trim()) config[k] = k === 'smtp_port' ? Number(v) : v.trim()
      }
      if (boardReport) config.posture_report = true
    } else if (type === 'pagerduty') {
      if (!pdKey.trim()) return setError('Integration key is required')
      config.integration_key = pdKey.trim()
    } else if (type === 'opsgenie') {
      if (!ogKey.trim()) return setError('API key is required')
      config.api_key = ogKey.trim()
    } else if (type === 'jira') {
      if (!jira.base_url.trim()) return setError('Base URL is required (https://yourcompany.atlassian.net)')
      if (!jira.user_email.trim()) return setError('User email is required')
      if (!jira.api_token.trim()) return setError('API token is required')
      if (!jira.project_key.trim()) return setError('Project key is required')
      config.base_url = jira.base_url.trim()
      config.user_email = jira.user_email.trim()
      config.api_token = jira.api_token.trim()
      config.project_key = jira.project_key.trim().toUpperCase()
    } else if (type === 'webhook') {
      if (!hook.url.trim()) return setError('Webhook URL is required')
      config.url = hook.url.trim()
      if (hook.secret.trim()) config.secret = hook.secret.trim()
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

  const TYPE_TABS: { value: IntegrationType; label: string; icon: React.ReactNode }[] = [
    { value: 'slack', label: 'Slack', icon: <Slack className="w-4 h-4" /> },
    { value: 'teams', label: 'Teams', icon: <MessageSquare className="w-4 h-4" /> },
    { value: 'email', label: 'Email', icon: <Mail className="w-4 h-4" /> },
    { value: 'pagerduty', label: 'PagerDuty', icon: <AlertTriangle className="w-4 h-4" /> },
    { value: 'opsgenie', label: 'OpsGenie', icon: <AlertTriangle className="w-4 h-4" /> },
    { value: 'jira', label: 'Jira', icon: <Ticket className="w-4 h-4" /> },
    { value: 'webhook', label: 'Webhook', icon: <Webhook className="w-4 h-4" /> },
  ]

  const showSeveritySelector = type === 'slack' || type === 'teams' || type === 'email'

  return (
    <Modal open onClose={onClose} title="Add integration" className="max-w-lg">
      <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        {TYPE_TABS.map(({ value, label, icon }) => (
          <button
            key={value}
            onClick={() => setType(value)}
            className={cn(
              'flex items-center gap-1.5 text-sm px-3 py-1.5 rounded-md transition-colors',
              type === value ? 'bg-accent/10 text-accent' : 'text-muted hover:text-white',
            )}
          >
            {icon}
            {label}
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
      ) : type === 'teams' ? (
        <div>
          <label className={label}>Microsoft Teams Incoming Webhook URL</label>
          <input
            className={input}
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="https://…webhook.office.com/webhookb2/…"
          />
        </div>
      ) : type === 'email' ? (
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
      ) : type === 'pagerduty' ? (
        <div className="space-y-3">
          <div>
            <label className={label}>Integration Key</label>
            <input
              className={input}
              type="password"
              value={pdKey}
              onChange={(e) => setPdKey(e.target.value)}
              placeholder="Events API v2 integration key from your PagerDuty service"
            />
          </div>
          <p className="text-xs text-muted">Triggers P1 incidents for SSVC &lsquo;Act&rsquo; findings</p>
        </div>
      ) : type === 'opsgenie' ? (
        <div className="space-y-3">
          <div>
            <label className={label}>API Key</label>
            <input
              className={input}
              type="password"
              value={ogKey}
              onChange={(e) => setOgKey(e.target.value)}
              placeholder="OpsGenie API key with Create/Update access"
            />
          </div>
          <p className="text-xs text-muted">Creates P1 alerts for SSVC &lsquo;Act&rsquo; findings</p>
        </div>
      ) : type === 'jira' ? (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={label}>Base URL</label>
              <input
                className={input}
                value={jira.base_url}
                onChange={(e) => setJira({ ...jira, base_url: e.target.value })}
                placeholder="https://yourcompany.atlassian.net"
              />
            </div>
            <div>
              <label className={label}>Project key</label>
              <input
                className={input}
                value={jira.project_key}
                onChange={(e) => setJira({ ...jira, project_key: e.target.value })}
                placeholder="SEC"
              />
            </div>
            <div>
              <label className={label}>User email</label>
              <input
                className={input}
                value={jira.user_email}
                onChange={(e) => setJira({ ...jira, user_email: e.target.value })}
                placeholder="bot@yourcompany.com"
              />
            </div>
            <div>
              <label className={label}>API token</label>
              <input
                className={input}
                type="password"
                value={jira.api_token}
                onChange={(e) => setJira({ ...jira, api_token: e.target.value })}
                placeholder="Atlassian API token"
              />
            </div>
          </div>
          <p className="text-xs text-muted">
            Create Jira issues from findings. After saving, use &ldquo;Test connection&rdquo; on the
            card to verify the credentials.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          <div>
            <label className={label}>Webhook URL</label>
            <input
              className={input}
              value={hook.url}
              onChange={(e) => setHook({ ...hook, url: e.target.value })}
              placeholder="https://automation.yourcompany.com/horus"
            />
          </div>
          <div>
            <label className={label}>Signing secret (optional)</label>
            <input
              className={input}
              type="password"
              value={hook.secret}
              onChange={(e) => setHook({ ...hook, secret: e.target.value })}
              placeholder="Used to HMAC-SHA256 sign the payload (X-Horus-Signature)"
            />
          </div>
          <p className="text-xs text-muted">
            POSTs a JSON event when a scan finds <span className="text-white">new critical
            findings</span>. Verify the body with HMAC-SHA256 of the secret against the
            X-Horus-Signature header.
          </p>
        </div>
      )}

      {showSeveritySelector && (
        <div className="flex items-center gap-3">
          <div className="flex-1">
            <label className={label}>Notify when severity is at least</label>
            <Select
              className="w-full"
              value={minSeverity}
              onValueChange={(v) => setMinSeverity(v)}
              options={SEVERITIES.map((s) => ({ value: s, label: s }))}
            />
          </div>
          <button onClick={onClose} className="self-end text-sm text-muted hover:text-white px-3 py-1.5">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={saving}
            className="self-end bg-accent text-bg font-medium text-sm px-4 py-1.5 rounded-md hover:bg-accent/90 disabled:opacity-50 transition-colors"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      )}

      {!showSeveritySelector && (
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="text-sm text-muted hover:text-white px-3 py-1.5">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={saving}
            className="bg-accent text-bg font-medium text-sm px-4 py-1.5 rounded-md hover:bg-accent/90 disabled:opacity-50 transition-colors"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      )}

      {error && <p className="text-xs text-severity-high">{error}</p>}
      </div>
    </Modal>
  )
}
