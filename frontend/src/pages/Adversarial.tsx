import { useEffect, useState } from 'react'
import { Swords, RefreshCw, ShieldAlert, ShieldCheck, Clock, History, CheckCircle, XCircle, Loader2 } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { RedFindingCard, type RedFinding } from '../components/adversarial/RedFindingCard'
import { RunProgress } from '../components/adversarial/RunProgress'
import { SeverityBadge } from '../components/findings/SeverityBadge'
import { cn } from '../lib/utils'
import { useRole } from '../hooks/useRole'

interface Stats {
  total: number
  by_status: Record<string, number>
  by_severity: Record<string, number>
  by_category: Record<string, number>
}

interface RunRecord {
  id: string
  status: 'running' | 'completed' | 'failed'
  findings_created: number
  responses_created: number
  started_at: string
  completed_at: string | null
  triggered_by: string
}

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info'] as const
const STATUSES   = ['', 'open', 'responded', 'accepted', 'false_positive'] as const
const CATEGORIES = ['', 'dns', 'ssl', 'headers', 'exposed_path', 'subdomain', 'breach', 'exploit', 'network', 'other'] as const

const select = 'bg-bg border border-border text-sm text-white rounded px-3 py-1.5 focus:outline-none focus:border-accent'

function timeAgo(iso: string) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000
  if (diff < 60)    return 'just now'
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return new Date(iso).toLocaleDateString()
}

function duration(start: string, end: string | null) {
  if (!end) return null
  const s = Math.round((new Date(end).getTime() - new Date(start).getTime()) / 1000)
  if (s < 60)   return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}

export default function Adversarial() {
  const { can } = useRole()
  const [findings, setFindings] = useState<RedFinding[]>([])
  const [stats, setStats]       = useState<Stats | null>(null)
  const [loading, setLoading]   = useState(true)
  const [running, setRunning]   = useState(false)
  const [toast, setToast]       = useState('')

  const [severity, setSeverity]   = useState('')
  const [status, setStatus]       = useState('')
  const [category, setCategory]   = useState('')

  // liveRunId: ID of a currently-running cycle (disables button)
  // modalRunId: which run the progress modal is currently showing
  const [liveRunId, setLiveRunId]   = useState<string | null>(null)
  const [modalRunId, setModalRunId] = useState<string | null>(null)

  const [runs, setRuns]             = useState<RunRecord[]>([])
  const [historyLoading, setHistoryLoading] = useState(true)

  const loadFindings = async () => {
    setLoading(true)
    const params = new URLSearchParams()
    if (severity) params.set('severity', severity)
    if (status)   params.set('status', status)
    if (category) params.set('category', category)

    const [f, s] = await Promise.all([
      api.get<RedFinding[]>(`/adversarial/findings?${params}`, 0).catch(() => []),
      api.get<Stats>('/adversarial/stats', 0).catch(() => null),
    ])
    setFindings(f)
    setStats(s)
    setLoading(false)
  }

  const loadHistory = () => {
    api.get<RunRecord[]>('/adversarial/history', 0)
      .then(setRuns)
      .catch(() => {})
      .finally(() => setHistoryLoading(false))
  }

  useEffect(() => { loadFindings() }, [severity, status, category])
  useEffect(() => { loadHistory() }, [])

  const runCycle = async () => {
    setRunning(true)
    try {
      const result = await api.post<{ run_id: string; status: string }>('/adversarial/run', {})
      setLiveRunId(result.run_id)
      setModalRunId(result.run_id)
    } catch (e) {
      setToast(friendlyErrorMessage(e, 'Failed to start cycle'))
      setTimeout(() => setToast(''), 4000)
    } finally {
      setRunning(false)
    }
  }

  const handleRunDone = () => {
    loadFindings()
    loadHistory()
  }

  const handleModalClose = () => {
    if (modalRunId === liveRunId) setLiveRunId(null)
    setModalRunId(null)
  }

  const openRun = (runId: string, isLive: boolean) => {
    if (isLive) {
      setLiveRunId(runId)
    }
    setModalRunId(runId)
  }

  const openCount      = stats?.by_status?.open      ?? 0
  const respondedCount = stats?.by_status?.responded ?? 0

  return (
    <div className="space-y-6">

      {/* ── Header ────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Swords className="w-5 h-5 text-horus-gold" />
          <h1 className="text-lg font-semibold">Red / Blue Agents</h1>
        </div>
        {can('admin') && (
          <button
            onClick={runCycle}
            disabled={running || liveRunId !== null}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-horus-lapis text-white text-sm font-medium hover:bg-horus-lapis/80 disabled:opacity-50 transition-colors"
          >
            <RefreshCw className={cn('w-4 h-4', (running || liveRunId) && 'animate-spin')} />
            {running ? 'Queuing…' : liveRunId ? 'Running…' : 'Run Cycle'}
          </button>
        )}
      </div>

      {toast && (
        <div className="glass border border-severity-critical/30 rounded-lg px-4 py-3 text-sm text-severity-critical">
          {toast}
        </div>
      )}

      {/* ── Stats bar ─────────────────────────────────────────────────────── */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Total findings" value={stats.total} />
          <StatCard label="Open" value={openCount} icon={<ShieldAlert className="w-4 h-4 text-accent" />} />
          <StatCard label="Responded" value={respondedCount} icon={<ShieldCheck className="w-4 h-4 text-mode-auto" />} />
          <div className="glass rounded-lg p-4 space-y-1.5">
            <p className="text-xs text-muted uppercase tracking-wide">By severity</p>
            <div className="flex flex-wrap gap-1.5">
              {['critical','high','medium','low'].map((sev) =>
                (stats.by_severity[sev] ?? 0) > 0 ? (
                  <span key={sev} className="flex items-center gap-1">
                    <SeverityBadge severity={sev} />
                    <span className="text-xs text-white/70">{stats.by_severity[sev]}</span>
                  </span>
                ) : null
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Filters ───────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap gap-3">
        <select className={select} value={severity} onChange={(e) => setSeverity(e.target.value)}>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s || 'All severities'}</option>)}
        </select>
        <select className={select} value={status} onChange={(e) => setStatus(e.target.value)}>
          {STATUSES.map((s) => <option key={s} value={s}>{s ? s.replace('_', ' ') : 'All statuses'}</option>)}
        </select>
        <select className={select} value={category} onChange={(e) => setCategory(e.target.value)}>
          {CATEGORIES.map((c) => <option key={c} value={c}>{c ? c.replace('_', ' ') : 'All categories'}</option>)}
        </select>
      </div>

      {/* ── Findings list ─────────────────────────────────────────────────── */}
      {loading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : findings.length === 0 ? (
        <div className="glass rounded-lg p-12 text-center">
          <Swords className="w-8 h-8 text-white/20 mx-auto mb-3" />
          <p className="text-white/40 text-sm">No findings yet.</p>
          {can('admin') && (
            <p className="text-white/30 text-xs mt-1">Click <strong>Run Cycle</strong> to start the Red agent.</p>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {findings.map((f) => (
            <RedFindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}

      {/* ── Run history ───────────────────────────────────────────────────── */}
      <div className="space-y-3">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-white/40" />
          <h2 className="text-sm font-medium text-white/60">Run history</h2>
        </div>

        {historyLoading ? (
          <p className="text-muted text-xs">Loading…</p>
        ) : runs.length === 0 ? (
          <p className="text-white/30 text-xs">No runs yet.</p>
        ) : (
          <div className="space-y-1.5">
            {runs.map((run) => (
              <RunRow
                key={run.id}
                run={run}
                isLive={run.id === liveRunId}
                onClick={() => openRun(run.id, run.id === liveRunId)}
              />
            ))}
          </div>
        )}
      </div>

      {/* ── Progress modal ────────────────────────────────────────────────── */}
      {modalRunId && (
        <RunProgress
          runId={modalRunId}
          isLive={modalRunId === liveRunId}
          title={modalRunId === liveRunId ? 'Adversarial Cycle — Live' : `Run log · ${timeAgo(runs.find(r => r.id === modalRunId)?.started_at ?? new Date().toISOString())}`}
          onClose={handleModalClose}
          onDone={handleRunDone}
        />
      )}
    </div>
  )
}

function RunRow({ run, isLive, onClick }: { run: RunRecord; isLive: boolean; onClick: () => void }) {
  const dur = duration(run.started_at, run.completed_at)

  return (
    <button
      onClick={onClick}
      className="w-full glass glass-hover rounded-lg px-4 py-3 flex items-center gap-4 text-left"
    >
      <div className="shrink-0">
        {run.status === 'running'   && <Loader2 className="w-4 h-4 text-accent animate-spin" />}
        {run.status === 'completed' && <CheckCircle className="w-4 h-4 text-mode-auto" />}
        {run.status === 'failed'    && <XCircle className="w-4 h-4 text-severity-critical" />}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm text-white/80">{timeAgo(run.started_at)}</span>
          {isLive && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent/15 text-accent border border-accent/30 uppercase tracking-wider">
              live
            </span>
          )}
          {run.triggered_by !== 'schedule' && (
            <span className="text-[10px] text-white/30">manual</span>
          )}
        </div>
        <div className="flex items-center gap-3 mt-0.5">
          {dur && (
            <span className="flex items-center gap-1 text-[11px] text-white/30">
              <Clock className="w-3 h-3" />{dur}
            </span>
          )}
        </div>
      </div>

      <div className="flex items-center gap-3 text-xs shrink-0">
        <span className="text-severity-critical">
          {run.findings_created} finding{run.findings_created !== 1 ? 's' : ''}
        </span>
        <span className="text-mode-auto">
          {run.responses_created} response{run.responses_created !== 1 ? 's' : ''}
        </span>
      </div>
    </button>
  )
}

function StatCard({ label, value, icon }: { label: string; value: number; icon?: React.ReactNode }) {
  return (
    <div className="glass rounded-lg p-4 flex items-center justify-between">
      <div>
        <p className="text-xs text-muted uppercase tracking-wide">{label}</p>
        <p className="text-2xl font-semibold mt-0.5">{value}</p>
      </div>
      {icon && <div className="opacity-70">{icon}</div>}
    </div>
  )
}
