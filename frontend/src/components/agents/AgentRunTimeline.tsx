import { useState } from 'react'
import { formatDistanceToNow } from 'date-fns'
import { CheckCircle, XCircle, Loader, Circle, ChevronDown, ChevronRight, Swords } from 'lucide-react'
import { cn } from '../../lib/utils'
import { VerdictBadge } from '../findings/VerdictBadge'

interface Debate {
  title: string
  verdict?: string | null
  rationale?: string | null
  red?: string | null
  blue?: string | null
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
  output_state?: { summary?: string; debates?: Debate[] } | null
}

const AGENT_LABELS: Record<string, string> = {
  recon: 'Recon',
  analyst: 'Analyst',
  correlation: 'Correlation',
  threat_intel: 'Threat Intel',
  validation: 'Validation',
  remediation: 'Remediation',
  risk_manager: 'Risk Manager',
  reporter: 'Reporter',
}

function StatusIcon({ status }: { status: string }) {
  if (status === 'completed') return <CheckCircle className="w-4 h-4 text-mode-auto" />
  if (status === 'failed') return <XCircle className="w-4 h-4 text-severity-critical" />
  if (status === 'running') return <Loader className="w-4 h-4 text-accent animate-spin" />
  return <Circle className="w-4 h-4 text-muted" />
}

// The red/blue deliberation for the validation step — the visible debate.
function Deliberation({ debates }: { debates: Debate[] }) {
  const [open, setOpen] = useState(false)
  const withArgs = debates.filter((d) => d.red || d.blue)
  if (!withArgs.length) return null

  return (
    <div className="mt-2">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 text-xs text-muted hover:text-white transition-colors"
      >
        {open ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
        <Swords className="w-3.5 h-3.5" />
        {open ? 'Hide' : 'Show'} deliberation ({withArgs.length})
      </button>
      {open && (
        <div className="mt-2 space-y-2">
          {withArgs.map((d, i) => (
            <div key={i} className="rounded border border-border bg-bg/40 p-2">
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className="text-xs font-medium text-white truncate">{d.title}</span>
                <VerdictBadge verdict={d.verdict} />
              </div>
              <div className="grid sm:grid-cols-2 gap-2">
                <p className="text-[11px] text-white/70 leading-snug">
                  <span className="text-severity-critical font-semibold">Red:</span> {d.red || '—'}
                </p>
                <p className="text-[11px] text-white/70 leading-snug">
                  <span className="text-mode-auto font-semibold">Blue:</span> {d.blue || '—'}
                </p>
              </div>
              {d.rationale && (
                <p className="text-[11px] text-muted mt-1">Judge: {d.rationale}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export function AgentRunTimeline({ runs }: { runs: AgentRun[] }) {
  return (
    <div className="space-y-2">
      {runs.map((run, i) => (
        <div key={run.id} className="flex gap-3">
          <div className="flex flex-col items-center">
            <StatusIcon status={run.status} />
            {i < runs.length - 1 && <div className="w-px flex-1 bg-border mt-1" />}
          </div>
          <div className="pb-4 min-w-0 flex-1">
            <div className="flex items-center gap-3">
              <span className="text-sm font-medium text-white">
                {AGENT_LABELS[run.agent_type] ?? run.agent_type}
              </span>
              {run.tokens_used > 0 && (
                <span className="text-xs text-muted">{run.tokens_used.toLocaleString()} tokens</span>
              )}
              {run.model_used && (
                <span className="text-xs text-muted font-mono">{run.model_used}</span>
              )}
            </div>
            {run.output_state?.summary && (
              <p className="text-xs text-white/70 mt-0.5">{run.output_state.summary}</p>
            )}
            {run.agent_type === 'validation' && run.output_state?.debates && (
              <Deliberation debates={run.output_state.debates} />
            )}
            {run.error_message && (
              <p className="text-xs text-severity-critical mt-0.5">{run.error_message}</p>
            )}
            {run.started_at && (
              <p className="text-xs text-muted mt-0.5">
                {formatDistanceToNow(new Date(run.started_at))} ago
              </p>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}
