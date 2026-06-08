import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { XCircle, FileText } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { AgentRunTimeline } from '../components/agents/AgentRunTimeline'
import { cn } from '../lib/utils'

interface ScanReport {
  summary: string
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  top_priorities: string[]
  recommended_next_steps: string
}

interface Scan {
  id: string
  status: string
  tools_used: string[]
  triggered_by: string
  triggered_by_label: string
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  report: ScanReport | null
  assets: { name: string; host: string }
  agent_runs: AgentRun[]
}

interface AgentRun {
  id: string
  agent_type: string
  status: string
  tokens_used: number
  model_used: string | null
  error_message: string | null
  started_at: string
  completed_at: string | null
}

const STATUS_COLOR: Record<string, string> = {
  completed: 'text-mode-auto',
  running: 'text-accent',
  failed: 'text-severity-critical',
  canceled: 'text-muted',
  pending: 'text-muted',
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<Scan | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [canceling, setCanceling] = useState(false)

  const load = useCallback(async () => {
    if (!id) return null
    try {
      const data = await api.get<Scan>(`/scans/${id}`)
      setScan(data)
      setError(null)
      return data
    } catch (e: unknown) {
      setError(friendlyErrorMessage(e, 'Failed to load scan'))
      return null
    }
  }, [id])

  useEffect(() => {
    if (!id) return
    let active = true
    let interval: number | undefined

    const poll = async () => {
      const data = await load()
      if (!active || !data) return
      if (data.status !== 'pending' && data.status !== 'running' && interval) {
        window.clearInterval(interval)
      }
    }

    poll()
    interval = window.setInterval(poll, 2500)

    return () => {
      active = false
      if (interval) window.clearInterval(interval)
    }
  }, [id, load])

  const cancelScan = async () => {
    if (!id) return
    setCanceling(true)
    try {
      await api.post(`/scans/${id}/cancel`)
      await load()
    } catch (e: unknown) {
      setError(friendlyErrorMessage(e, 'Failed to cancel scan'))
    } finally {
      setCanceling(false)
    }
  }

  if (error) return <p className="text-severity-critical text-sm">{error}</p>
  if (!scan) return <p className="text-muted text-sm">Loading…</p>

  const totalTokens = scan.agent_runs.reduce((sum, r) => sum + (r.tokens_used ?? 0), 0)
  const displayStatus = scan.status === 'failed' && scan.error_message === 'Canceled by user'
    ? 'canceled'
    : scan.status

  return (
    <div className="max-w-2xl space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold">{scan.assets?.name}</h1>
          <p className="text-sm text-muted">{scan.assets?.host}</p>
        </div>
        {(scan.status === 'pending' || scan.status === 'running') && (
          <button
            onClick={cancelScan}
            disabled={canceling}
            className="flex items-center gap-2 border border-border px-3 py-2 text-xs text-muted hover:text-severity-critical disabled:cursor-wait disabled:opacity-40"
          >
            <XCircle className="h-4 w-4" />
            Cancel Scan
          </button>
        )}
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="bg-surface border border-border rounded-lg p-4">
          <p className="text-xs text-muted uppercase mb-1">Status</p>
          <p className={cn('text-sm font-medium capitalize', STATUS_COLOR[displayStatus])}>{displayStatus}</p>
        </div>
        <div className="bg-surface border border-border rounded-lg p-4">
          <p className="text-xs text-muted uppercase mb-1">Tools</p>
          <p className="text-sm text-white">{scan.tools_used.join(', ')}</p>
        </div>
        <div className="bg-surface border border-border rounded-lg p-4">
          <p className="text-xs text-muted uppercase mb-1">Total Tokens</p>
          <p className="text-sm text-white">{totalTokens.toLocaleString()}</p>
        </div>
      </div>

      <div className="bg-surface border border-border rounded-lg p-4">
        <p className="text-xs text-muted uppercase mb-1">Triggered By</p>
        <p className="text-sm text-white">{scan.triggered_by_label}</p>
      </div>

      {scan.error_message && (
        <div className="bg-severity-critical/10 border border-severity-critical/30 rounded-lg p-4">
          <p className="text-sm text-severity-critical">{scan.error_message}</p>
        </div>
      )}

      {scan.report && (scan.report.summary || scan.report.recommended_next_steps) && (
        <div className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-medium text-muted uppercase mb-3 flex items-center gap-1.5">
            <FileText className="w-4 h-4 text-accent" /> Executive summary
          </h2>
          {scan.report.summary && (
            <p className="text-sm text-white/85 leading-relaxed">{scan.report.summary}</p>
          )}
          <div className="flex flex-wrap gap-3 mt-3 text-xs">
            {([
              ['critical', scan.report.critical_count, 'text-severity-critical border-severity-critical/30'],
              ['high', scan.report.high_count, 'text-severity-high border-severity-high/30'],
              ['medium', scan.report.medium_count, 'text-severity-medium border-severity-medium/30'],
              ['low', scan.report.low_count, 'text-severity-low border-severity-low/30'],
            ] as const).map(([sev, n, cls]) => (
              <span key={sev} className={cn('px-2 py-0.5 rounded border bg-white/[0.02]', cls)}>
                {n} {sev}
              </span>
            ))}
          </div>
          {scan.report.recommended_next_steps && (
            <div className="mt-4">
              <p className="text-xs font-medium text-muted uppercase mb-1">Recommended next steps</p>
              <p className="text-sm text-white/80 leading-relaxed whitespace-pre-line">
                {scan.report.recommended_next_steps}
              </p>
            </div>
          )}
        </div>
      )}

      <div className="bg-surface border border-border rounded-lg p-5">
        <h2 className="text-sm font-medium text-muted uppercase mb-4">Agent Pipeline</h2>
        <AgentRunTimeline runs={scan.agent_runs} />
      </div>
    </div>
  )
}
