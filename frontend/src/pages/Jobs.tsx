import { useEffect, useRef, useState } from 'react'
import { formatDistanceToNow } from 'date-fns'
import {
  Activity, Clock, Radar, Database, Eye, TrendingUp, FileText, Swords,
  CheckCircle, XCircle, Loader, StopCircle, Ban,
} from 'lucide-react'
import { api } from '../lib/api'
import { cn } from '../lib/utils'
import { useRole } from '../hooks/useRole'

interface Job {
  id: string
  job_type: string
  status: string
  trigger: string
  detail: Record<string, unknown> | null
  error: string | null
  started_at: string
  finished_at: string | null
  duration_ms: number | null
}

const TYPES: Record<string, { label: string; Icon: typeof Clock }> = {
  scan_schedule:    { label: 'Scheduled scan',     Icon: Clock },
  discovery:        { label: 'Discovery',           Icon: Radar },
  cve_sync:         { label: 'CVE intel sync',      Icon: Database },
  watchtower:       { label: 'Watchtower',          Icon: Eye },
  posture_snapshot: { label: 'Posture snapshot',    Icon: TrendingUp },
  posture_report:   { label: 'Board report',        Icon: FileText },
  adversarial:      { label: 'Adversarial cycle',   Icon: Swords },
}

const STATUS: Record<string, { cls: string; Icon: typeof CheckCircle }> = {
  completed: { cls: 'text-mode-auto',           Icon: CheckCircle },
  failed:    { cls: 'text-severity-critical',   Icon: XCircle },
  running:   { cls: 'text-accent',              Icon: Loader },
  canceled:  { cls: 'text-white/40',            Icon: Ban },
}

const TYPE_FILTERS   = ['', ...Object.keys(TYPES)]
const STATUS_FILTERS = ['', 'running', 'completed', 'failed', 'canceled']

const POLL_INTERVAL = 5000 // ms — refresh while any job is running

function fmtDuration(ms: number | null): string {
  if (ms == null) return '—'
  if (ms < 1000) return `${ms} ms`
  const s = ms / 1000
  return s < 60 ? `${s.toFixed(1)} s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`
}

// Raw backend errors (Python tracebacks, httpx noise…) erode trust when shown verbatim.
// Map known shapes to a human summary; the raw text stays available under "Technical
// details". Add new patterns at the top — first match wins.
const ERROR_PATTERNS: { test: RegExp; message: string }[] = [
  {
    // Python runtime errors leaking from the job runner itself
    test: /name '[^']*' is not defined|Traceback \(most recent call last\)|(?:^|\s)(?:NameError|AttributeError|TypeError|KeyError|IndexError|UnboundLocalError):/i,
    message: "Internal error during job execution — our team's agent hit a bug.",
  },
  {
    // Transient network / connectivity failures
    test: /server disconnected|connection (?:reset|refused|aborted|closed)|timed? ?out|timeout|temporarily unavailable|ECONNRESET|ECONNREFUSED|EOF occurred|RemoteProtocolError|ReadError|ConnectError/i,
    message: 'The job lost connection to the target or backend and was interrupted. Retrying usually fixes this.',
  },
  {
    // Job was stopped by an operator
    test: /cancell?ed by|job cancell?ed/i,
    message: 'Job was stopped by an operator.',
  },
]

export function humanizeJobError(raw: string): string {
  for (const { test, message } of ERROR_PATTERNS) {
    if (test.test(raw)) return message
  }
  return 'Job failed.'
}

function fmtDetail(detail: Record<string, unknown> | null): string {
  if (!detail) return ''
  const parts = Object.entries(detail)
    .filter(([k]) => k !== 'error')
    .map(([k, v]) => `${k.replace(/_/g, ' ')}: ${v}`)
  return parts.join(' · ')
}

export default function Jobs() {
  const { can } = useRole()
  const [jobs, setJobs]       = useState<Job[]>([])
  const [loading, setLoading] = useState(true)
  const [type, setType]       = useState('')
  const [status, setStatus]   = useState('')
  const [stopping, setStopping] = useState<Record<string, boolean>>({})
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const loadJobs = async (showSpinner = false) => {
    if (showSpinner) setLoading(true)
    const params = new URLSearchParams()
    if (type)   params.set('job_type', type)
    if (status) params.set('status', status)
    try {
      const data = await api.get<Job[]>(`/jobs?${params}`)
      setJobs(data)
      return data
    } finally {
      if (showSpinner) setLoading(false)
    }
  }

  // Start / stop the auto-refresh poll based on whether any job is running
  const syncPoll = (data: Job[]) => {
    const hasRunning = data.some((j) => j.status === 'running')
    if (hasRunning && !pollRef.current) {
      pollRef.current = setInterval(() => loadJobs().then(syncPoll), POLL_INTERVAL)
    } else if (!hasRunning && pollRef.current) {
      clearInterval(pollRef.current)
      pollRef.current = null
    }
  }

  useEffect(() => {
    loadJobs(true).then(syncPoll)
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [type, status])

  const cancelJob = async (job: Job) => {
    setStopping((prev) => ({ ...prev, [job.id]: true }))
    try {
      await api.post(`/jobs/${job.id}/cancel`, {})
      await loadJobs().then(syncPoll)
    } catch {
      // If it fails the job may have already finished — just refresh
      await loadJobs().then(syncPoll)
    } finally {
      setStopping((prev) => ({ ...prev, [job.id]: false }))
    }
  }

  const select = 'bg-bg border border-border text-sm text-white rounded px-3 py-1.5 focus:outline-none focus:border-accent'

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-accent" />
          <h1 className="text-lg font-semibold">Job history</h1>
        </div>
        <div className="flex gap-3">
          <select className={select} value={type} onChange={(e) => setType(e.target.value)}>
            {TYPE_FILTERS.map((t) => (
              <option key={t} value={t}>{t ? TYPES[t]?.label ?? t : 'All types'}</option>
            ))}
          </select>
          <select className={select} value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUS_FILTERS.map((s) => (
              <option key={s} value={s}>{s || 'All statuses'}</option>
            ))}
          </select>
        </div>
      </div>

      <p className="text-sm text-muted -mt-2">
        Every background run — scheduled scans, discovery, the daily CVE sync, Watchtower, posture
        snapshots and the board report. Proof the platform is working on its own.
      </p>

      {loading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : jobs.length === 0 ? (
        <p className="text-muted text-sm">No jobs have run yet.</p>
      ) : (
        <div className="space-y-2">
          {jobs.map((job) => {
            const t = TYPES[job.job_type] ?? { label: job.job_type, Icon: Activity }
            const s = STATUS[job.status]  ?? { cls: 'text-muted',  Icon: Activity }
            const detail = fmtDetail(job.detail)
            const isStopping = stopping[job.id] ?? false

            return (
              <div
                key={job.id}
                className="bg-surface border border-border rounded-lg p-4 flex items-start justify-between gap-4"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <t.Icon className="w-4 h-4 text-accent shrink-0 mt-0.5" />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-white">{t.label}</span>
                      {job.trigger === 'manual' && (
                        <span className="text-[10px] uppercase tracking-wide text-muted border border-border rounded px-1.5 py-0.5">
                          manual
                        </span>
                      )}
                    </div>
                    {detail && <p className="text-xs text-muted mt-0.5 truncate">{detail}</p>}
                    {job.error && (
                      <div className="mt-0.5">
                        <p className="text-xs text-severity-critical">{humanizeJobError(job.error)}</p>
                        <details className="mt-0.5">
                          <summary className="text-[11px] text-muted cursor-pointer hover:text-white/70 select-none">
                            Technical details
                          </summary>
                          <pre className="text-[11px] text-muted mt-1 p-2 bg-bg border border-border rounded whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                            {job.error}
                          </pre>
                        </details>
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0 text-xs">
                  <span className="text-muted">{fmtDuration(job.duration_ms)}</span>
                  <span className="text-muted whitespace-nowrap">
                    {formatDistanceToNow(new Date(job.started_at))} ago
                  </span>
                  <span className={cn('flex items-center gap-1 capitalize', s.cls)}>
                    <s.Icon className={cn('w-4 h-4', job.status === 'running' && 'animate-spin')} />
                    {job.status}
                  </span>

                  {can('admin') && job.status === 'running' && (
                    <button
                      onClick={() => cancelJob(job)}
                      disabled={isStopping}
                      title="Stop job"
                      className="flex items-center gap-1 px-2 py-1 rounded text-severity-critical/80 border border-severity-critical/30 hover:bg-severity-critical/10 disabled:opacity-40 transition-colors"
                    >
                      {isStopping
                        ? <Loader className="w-3.5 h-3.5 animate-spin" />
                        : <StopCircle className="w-3.5 h-3.5" />}
                      <span className="text-[11px]">{isStopping ? 'Stopping…' : 'Stop'}</span>
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
