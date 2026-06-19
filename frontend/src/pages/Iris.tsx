import { useEffect, useState, useCallback } from 'react'
import {
  Radio,
  Plus,
  Trash2,
  Zap,
  List,
  X,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Terminal,
} from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { SeverityBadge } from '../components/findings/SeverityBadge'
import { cn } from '../lib/utils'

// Backend API base — in dev the backend is on :8000, in prod same origin
const API_BASE = import.meta.env.VITE_API_BASE_URL ||
  (window.location.port === '5173'
    ? `${window.location.protocol}//${window.location.hostname}:8000`
    : window.location.origin)

// ── Types ────────────────────────────────────────────────────────────────────

interface IrisAgent {
  id: string
  name: string
  hostname: string | null
  platform: string | null
  ip: string | null
  status: 'online' | 'offline' | 'degraded'
  last_seen_at: string | null
  created_at: string
  key_prefix: string
  config: { watch_paths?: string[]; interval_seconds?: number }
  pending_events?: number
  asset_id: string | null
}

interface IrisEvent {
  id: string
  event_type:
    | 'file_change'
    | 'new_process'
    | 'new_listener'
    | 'new_connection'
    | 'auth_event'
    | 'log_anomaly'
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  title: string
  payload: Record<string, unknown>
  received_at: string
}

interface AssetOption {
  id: string
  name: string
}

interface RegisterResult {
  agent_id: string
  api_key: string
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function relativeTime(iso: string | null): string {
  if (!iso) return 'never'
  const diff = Date.now() - new Date(iso).getTime()
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function agentStatusFromLastSeen(_declared: IrisAgent['status'], lastSeen: string | null): IrisAgent['status'] {
  if (!lastSeen) return 'offline'
  const mins = (Date.now() - new Date(lastSeen).getTime()) / 60000
  if (mins < 2) return 'online'
  if (mins < 10) return 'degraded'
  return 'offline'
}

function StatusDot({ agent }: { agent: IrisAgent }) {
  const status = agentStatusFromLastSeen(agent.status, agent.last_seen_at)
  return (
    <span
      className={cn(
        'inline-block w-2 h-2 rounded-full shrink-0',
        status === 'online' && 'bg-green-400',
        status === 'degraded' && 'bg-yellow-400',
        status === 'offline' && 'bg-white/30',
      )}
      title={status}
    />
  )
}

function PlatformBadge({ platform }: { platform: string | null }) {
  if (!platform) return null
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border bg-white/5 border-white/10 text-white/60 uppercase tracking-wide">
      {platform}
    </span>
  )
}

function EventTypeBadge({ type }: { type: IrisEvent['event_type'] }) {
  const map: Record<IrisEvent['event_type'], string> = {
    file_change: 'bg-blue-500/10 border-blue-500/30 text-blue-300',
    new_process: 'bg-purple-500/10 border-purple-500/30 text-purple-300',
    new_listener: 'bg-orange-500/10 border-orange-500/30 text-orange-300',
    new_connection: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300',
    auth_event: 'bg-red-500/10 border-red-500/30 text-red-300',
    log_anomaly: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-300',
  }
  const label = type.replace(/_/g, ' ')
  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border uppercase tracking-wide',
        map[type] ?? 'bg-white/5 border-white/10 text-white/60',
      )}
    >
      {label}
    </span>
  )
}

function useCopyToClipboard(): [boolean, (text: string) => void] {
  const [copied, setCopied] = useState(false)
  const copy = useCallback((text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [])
  return [copied, copy]
}

function CopyButton({ text, className }: { text: string; className?: string }) {
  const [copied, copy] = useCopyToClipboard()
  return (
    <button
      onClick={() => copy(text)}
      className={cn(
        'flex items-center gap-1 text-xs px-2 py-1 rounded border transition-colors',
        copied
          ? 'border-green-500/40 text-green-400 bg-green-500/10'
          : 'border-white/10 text-white/50 hover:text-white hover:border-white/30',
        className,
      )}
      title="Copy to clipboard"
    >
      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function Iris() {
  const [agents, setAgents] = useState<IrisAgent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showRegister, setShowRegister] = useState(false)
  const [eventsAgent, setEventsAgent] = useState<IrisAgent | null>(null)

  const load = useCallback(async () => {
    try {
      const data = await api.get<IrisAgent[]>('/iris/agents', 0)
      setAgents(data)
      setError(null)
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Failed to load agents'))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const timer = setInterval(load, 30000)
    return () => clearInterval(timer)
  }, [load])

  const deleteAgent = async (agent: IrisAgent) => {
    const uninstallCmd = `curl -sSL ${API_BASE}/api/iris/uninstall.sh | sudo bash`
    if (!confirm(
      `Delete agent "${agent.name}" from the dashboard?\n\n` +
      `This only removes the DB record. To also remove the daemon from the server, run:\n\n${uninstallCmd}`
    )) return
    try {
      await api.delete(`/iris/agents/${agent.id}`)
      load()
    } catch (e) {
      alert(friendlyErrorMessage(e, 'Failed to delete agent'))
    }
  }

  const analyzeAgent = async (agent: IrisAgent) => {
    try {
      await api.post<{ scan_id: string }>(`/iris/agents/${agent.id}/process`)
      alert(`Analysis triggered for "${agent.name}"`)
    } catch (e) {
      alert(friendlyErrorMessage(e, 'Failed to trigger analysis'))
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-horus-ivory flex items-center gap-2">
            <Radio className="w-5 h-5 text-horus-gold" />
            Iris Agents
            {agents.length > 0 && (
              <span className="ml-1 text-xs font-medium bg-white/10 border border-white/10 text-white/70 px-2 py-0.5 rounded-full">
                {agents.length}
              </span>
            )}
          </h1>
          <p className="text-sm text-muted mt-1">
            Lightweight host agents that stream file, process, and auth events in real time.
          </p>
        </div>
        <button
          onClick={() => setShowRegister(true)}
          className="flex items-center gap-2 text-sm bg-horus-lapis text-white px-3 py-2 rounded-md hover:opacity-90 transition-opacity shrink-0"
        >
          <Plus className="w-4 h-4" /> Register Agent
        </button>
      </div>

      {error && (
        <div className="border border-severity-critical/40 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical rounded-md">
          {error}
        </div>
      )}

      {/* Agent list */}
      {loading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : agents.length === 0 ? (
        <EmptyState onRegister={() => setShowRegister(true)} />
      ) : (
        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-xs text-muted">
                <th className="text-left py-3 px-4 font-medium">Agent</th>
                <th className="text-left py-3 px-4 font-medium">Platform</th>
                <th className="text-left py-3 px-4 font-medium">IP</th>
                <th className="text-left py-3 px-4 font-medium">Last seen</th>
                <th className="text-left py-3 px-4 font-medium">Events</th>
                <th className="py-3 px-4" />
              </tr>
            </thead>
            <tbody>
              {agents.map((agent) => (
                <tr
                  key={agent.id}
                  className="border-b border-border last:border-0 hover:bg-white/[0.02] transition-colors"
                >
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <StatusDot agent={agent} />
                      <div>
                        <p className="font-medium text-horus-ivory">{agent.name}</p>
                        {agent.hostname && (
                          <p className="text-xs text-muted">{agent.hostname}</p>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <PlatformBadge platform={agent.platform} />
                  </td>
                  <td className="py-3 px-4 text-xs text-muted font-mono">
                    {agent.ip ?? '—'}
                  </td>
                  <td className="py-3 px-4 text-xs text-muted">
                    {relativeTime(agent.last_seen_at)}
                  </td>
                  <td className="py-3 px-4 text-xs text-muted">
                    {agent.pending_events ?? 0}
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => setEventsAgent(agent)}
                        className="flex items-center gap-1 text-xs text-white/50 hover:text-white px-2 py-1 rounded hover:bg-white/10 transition-colors"
                        title="View events"
                      >
                        <List className="w-3.5 h-3.5" />
                        Events
                      </button>
                      <button
                        onClick={() => analyzeAgent(agent)}
                        className="flex items-center gap-1 text-xs text-white/50 hover:text-horus-gold px-2 py-1 rounded hover:bg-white/10 transition-colors"
                        title="Trigger analysis"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        Analyze
                      </button>
                      <button
                        onClick={() => deleteAgent(agent)}
                        className="text-muted hover:text-severity-critical transition-colors p-1 rounded hover:bg-white/10"
                        title="Delete agent"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Modals / panels */}
      {showRegister && (
        <RegisterAgentModal
          onClose={() => setShowRegister(false)}
          onRegistered={() => {
            load()
          }}
        />
      )}

      {eventsAgent && (
        <AgentEventsPanel
          agent={eventsAgent}
          onClose={() => setEventsAgent(null)}
        />
      )}
    </div>
  )
}

// ── Empty State ───────────────────────────────────────────────────────────────

function EmptyState({ onRegister }: { onRegister: () => void }) {
  return (
    <div className="glass rounded-lg p-12 text-center space-y-4">
      <div className="w-12 h-12 rounded-full glass flex items-center justify-center mx-auto">
        <Radio className="w-6 h-6 text-muted" />
      </div>
      <div>
        <p className="text-horus-ivory font-medium">No agents registered yet</p>
        <p className="text-muted text-sm mt-1">
          Deploy Iris on any Linux or macOS host to start collecting real-time events.
        </p>
      </div>
      <button
        onClick={onRegister}
        className="inline-flex items-center gap-2 text-sm bg-horus-lapis text-white px-4 py-2 rounded-md hover:opacity-90 transition-opacity"
      >
        <Plus className="w-4 h-4" /> Register your first agent
      </button>
    </div>
  )
}

// ── Register Agent Modal ──────────────────────────────────────────────────────

function RegisterAgentModal({
  onClose,
  onRegistered,
}: {
  onClose: () => void
  onRegistered: () => void
}) {
  const [name, setName] = useState('')
  const [assetId, setAssetId] = useState('')
  const [assets, setAssets] = useState<AssetOption[]>([])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<RegisterResult | null>(null)

  useEffect(() => {
    api.get<{ id: string; name: string }[]>('/assets').then(setAssets).catch(() => {})
  }, [])

  const submit = async () => {
    if (!name.trim() || saving) return
    setSaving(true)
    setError('')
    try {
      const res = await api.post<RegisterResult>('/iris/agents/register', {
        name: name.trim(),
        asset_id: assetId || undefined,
      })
      setResult(res)
      onRegistered()
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Failed to register agent'))
      setSaving(false)
    }
  }

  const serverUrl = API_BASE

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="glass rounded-lg p-6 w-full max-w-xl space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-horus-ivory flex items-center gap-2">
            <Radio className="w-4 h-4 text-horus-gold" />
            Register Agent
          </h2>
          <button onClick={onClose} className="text-muted hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>

        {result ? (
          <InstallInstructions result={result} serverUrl={serverUrl} onClose={onClose} />
        ) : (
          <>
            <Field label="Agent name">
              <input
                autoFocus
                value={name}
                onChange={(e) => setName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && submit()}
                placeholder="e.g. prod-web-01"
                className="w-full glass rounded-md px-3 py-2 text-sm text-horus-ivory bg-transparent border border-white/10 focus:outline-none focus:border-horus-lapis"
              />
            </Field>

            <Field label="Asset (optional)">
              <select
                value={assetId}
                onChange={(e) => setAssetId(e.target.value)}
                className="w-full glass rounded-md px-3 py-2 text-sm text-horus-ivory bg-transparent border border-white/10 focus:outline-none focus:border-horus-lapis"
              >
                <option value="" className="bg-bg text-white/60">
                  — none —
                </option>
                {assets.map((a) => (
                  <option key={a.id} value={a.id} className="bg-bg">
                    {a.name}
                  </option>
                ))}
              </select>
            </Field>

            {error && <p className="text-xs text-severity-high">{error}</p>}

            <div className="flex justify-end gap-2 pt-2">
              <button onClick={onClose} className="text-sm text-muted hover:text-white px-3 py-2">
                Cancel
              </button>
              <button
                onClick={submit}
                disabled={!name.trim() || saving}
                className="flex items-center gap-2 text-sm bg-horus-lapis text-white px-4 py-2 rounded-md hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Plus className="w-4 h-4" />
                {saving ? 'Registering…' : 'Register'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function InstallInstructions({
  result,
  serverUrl,
  onClose,
}: {
  result: RegisterResult
  serverUrl: string
  onClose: () => void
}) {
  const installCmd = `curl -sSL "${serverUrl}/api/iris/install.sh?api_key=${result.api_key}&agent_id=${result.agent_id}" | sudo bash`

  return (
    <div className="space-y-4">
      {/* Warning */}
      <div className="flex items-start gap-2 bg-yellow-500/10 border border-yellow-500/30 rounded-md px-3 py-2">
        <span className="text-yellow-400 text-base leading-none mt-0.5">⚠</span>
        <p className="text-xs text-yellow-300">
          The API key is shown only once. Copy it now — it cannot be recovered.
        </p>
      </div>

      {/* API Key */}
      <div>
        <p className="text-xs font-medium text-muted uppercase tracking-wide mb-1">API Key</p>
        <div className="flex items-center gap-2">
          <code className="flex-1 glass rounded-md px-3 py-2 text-sm font-mono text-horus-ivory border border-white/10 select-all break-all">
            {result.api_key}
          </code>
          <CopyButton text={result.api_key} />
        </div>
      </div>

      {/* Install command */}
      <div>
        <div className="flex items-center justify-between mb-1">
          <p className="text-xs font-medium text-muted uppercase tracking-wide">Install command</p>
          <CopyButton text={installCmd} />
        </div>
        <pre className="glass rounded-md px-3 py-2 text-xs font-mono text-white/80 border border-white/10 whitespace-pre-wrap break-all">
          {installCmd}
        </pre>
      </div>

      {/* Manual config */}
      <div>
        <p className="text-xs font-medium text-muted uppercase tracking-wide mb-1">Manual config</p>
        <div className="glass rounded-md px-3 py-3 text-xs font-mono border border-white/10 space-y-1">
          <div className="flex gap-3">
            <span className="text-muted w-24 shrink-0">Server URL</span>
            <span className="text-horus-ivory">{serverUrl}</span>
          </div>
          <div className="flex gap-3">
            <span className="text-muted w-24 shrink-0">Agent ID</span>
            <span className="text-horus-ivory">{result.agent_id}</span>
          </div>
          <div className="flex gap-3">
            <span className="text-muted w-24 shrink-0">API Key</span>
            <span className="text-horus-ivory">{result.api_key}</span>
          </div>
        </div>
      </div>

      <div className="flex justify-end pt-2">
        <button
          onClick={onClose}
          className="text-sm bg-horus-lapis text-white px-4 py-2 rounded-md hover:opacity-90"
        >
          Done
        </button>
      </div>
    </div>
  )
}

// ── Agent Events Panel ────────────────────────────────────────────────────────

function AgentEventsPanel({
  agent,
  onClose,
}: {
  agent: IrisAgent
  onClose: () => void
}) {
  const [events, setEvents] = useState<IrisEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  useEffect(() => {
    setLoading(true)
    api
      .get<IrisEvent[]>(`/iris/agents/${agent.id}/events?limit=50`, 0)
      .then((data) => {
        setEvents(data)
        setError(null)
      })
      .catch((e) => setError(friendlyErrorMessage(e, 'Failed to load events')))
      .finally(() => setLoading(false))
  }, [agent.id])

  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const status = agentStatusFromLastSeen(agent.status, agent.last_seen_at)

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40 bg-black/40" onClick={onClose} />

      {/* Slide-in panel */}
      <div className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-lg flex flex-col glass border-l border-white/10 shadow-2xl">
        {/* Panel header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/10">
          <div className="flex items-center gap-3 min-w-0">
            <span
              className={cn(
                'inline-block w-2 h-2 rounded-full shrink-0',
                status === 'online' && 'bg-green-400',
                status === 'degraded' && 'bg-yellow-400',
                status === 'offline' && 'bg-white/30',
              )}
            />
            <div className="min-w-0">
              <p className="font-semibold text-horus-ivory truncate">{agent.name}</p>
              {agent.hostname && (
                <p className="text-xs text-muted truncate">{agent.hostname}</p>
              )}
            </div>
          </div>
          <button onClick={onClose} className="text-muted hover:text-white shrink-0 ml-3">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Event list */}
        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <p className="text-muted text-sm p-5">Loading events…</p>
          ) : error ? (
            <p className="text-severity-high text-xs p-5">{error}</p>
          ) : events.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-center p-8">
              <Terminal className="w-8 h-8 text-muted" />
              <p className="text-muted text-sm">No events received yet from this agent.</p>
            </div>
          ) : (
            <ul className="divide-y divide-white/5">
              {events.map((ev) => {
                const isExpanded = expanded.has(ev.id)
                return (
                  <li key={ev.id} className="px-5 py-3">
                    <div className="flex items-start gap-3">
                      <div className="flex flex-col gap-1 min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <SeverityBadge severity={ev.severity} />
                          <EventTypeBadge type={ev.event_type} />
                        </div>
                        <p className="text-sm text-horus-ivory mt-1">{ev.title}</p>
                        <p className="text-xs text-muted">{relativeTime(ev.received_at)}</p>
                      </div>
                      <button
                        onClick={() => toggleExpand(ev.id)}
                        className="text-muted hover:text-white transition-colors shrink-0 mt-0.5"
                        title={isExpanded ? 'Collapse payload' : 'Expand payload'}
                      >
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4" />
                        ) : (
                          <ChevronRight className="w-4 h-4" />
                        )}
                      </button>
                    </div>
                    {isExpanded && (
                      <pre className="mt-2 glass rounded-md px-3 py-2 text-xs font-mono text-white/70 border border-white/10 overflow-x-auto">
                        {JSON.stringify(ev.payload, null, 2)}
                      </pre>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
        </div>
      </div>
    </>
  )
}

// ── Shared helpers ────────────────────────────────────────────────────────────

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-muted uppercase tracking-wide">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  )
}
