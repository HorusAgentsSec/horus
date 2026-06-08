import { useEffect, useState } from 'react'
import { formatDistanceToNow } from 'date-fns'
import {
  Activity, Clock, Radar, Database, Eye, TrendingUp, FileText,
  CheckCircle, XCircle, Loader,
} from 'lucide-react'
import { api } from '../lib/api'
import { cn } from '../lib/utils'

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
  scan_schedule: { label: 'Scheduled scan', Icon: Clock },
  discovery: { label: 'Discovery', Icon: Radar },
  cve_sync: { label: 'CVE intel sync', Icon: Database },
  watchtower: { label: 'Watchtower', Icon: Eye },
  posture_snapshot: { label: 'Posture snapshot', Icon: TrendingUp },
  posture_report: { label: 'Board report', Icon: FileText },
}

const STATUS: Record<string, { cls: string; Icon: typeof CheckCircle }> = {
  completed: { cls: 'text-mode-auto', Icon: CheckCircle },
  failed: { cls: 'text-severity-critical', Icon: XCircle },
  running: { cls: 'text-accent', Icon: Loader },
}

const TYPE_FILTERS = ['', ...Object.keys(TYPES)]
const STATUS_FILTERS = ['', 'completed', 'failed', 'running']

function fmtDuration(ms: number | null): string {
  if (ms == null) return '—'
  if (ms < 1000) return `${ms} ms`
  const s = ms / 1000
  return s < 60 ? `${s.toFixed(1)} s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`
}

function fmtDetail(detail: Record<string, unknown> | null): string {
  if (!detail) return ''
  const parts = Object.entries(detail)
    .filter(([k]) => k !== 'error')
    .map(([k, v]) => `${k.replace(/_/g, ' ')}: ${v}`)
  return parts.join(' · ')
}

export default function Jobs() {
  const [jobs, setJobs] = useState<Job[]>([])
  const [loading, setLoading] = useState(true)
  const [type, setType] = useState('')
  const [status, setStatus] = useState('')

  useEffect(() => {
    setLoading(true)
    const params = new URLSearchParams()
    if (type) params.set('job_type', type)
    if (status) params.set('status', status)
    api.get<Job[]>(`/jobs?${params}`).then(setJobs).finally(() => setLoading(false))
  }, [type, status])

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
            const s = STATUS[job.status] ?? { cls: 'text-muted', Icon: Activity }
            const detail = fmtDetail(job.detail)
            return (
              <div key={job.id} className="bg-surface border border-border rounded-lg p-4 flex items-start justify-between gap-4">
                <div className="flex items-start gap-3 min-w-0">
                  <t.Icon className="w-4 h-4 text-accent shrink-0 mt-0.5" />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-white">{t.label}</span>
                      {job.trigger === 'manual' && (
                        <span className="text-[10px] uppercase tracking-wide text-muted border border-border rounded px-1.5 py-0.5">manual</span>
                      )}
                    </div>
                    {detail && <p className="text-xs text-muted mt-0.5 truncate">{detail}</p>}
                    {job.error && <p className="text-xs text-severity-critical mt-0.5 truncate">{job.error}</p>}
                  </div>
                </div>
                <div className="flex items-center gap-4 shrink-0 text-xs">
                  <span className="text-muted">{fmtDuration(job.duration_ms)}</span>
                  <span className="text-muted whitespace-nowrap">
                    {formatDistanceToNow(new Date(job.started_at))} ago
                  </span>
                  <span className={cn('flex items-center gap-1 capitalize', s.cls)}>
                    <s.Icon className={cn('w-4 h-4', job.status === 'running' && 'animate-spin')} />
                    {job.status}
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
