import { cn } from '../../lib/utils'
import type { IncidentStatus } from '../../lib/api'

const STATUS_STYLES: Record<IncidentStatus, string> = {
  open: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  in_progress: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  resolved: 'bg-green-500/10 text-green-400 border-green-500/30',
  closed: 'bg-white/5 text-muted border-white/10',
}

const STATUS_LABELS: Record<IncidentStatus, string> = {
  open: 'Open',
  in_progress: 'In progress',
  resolved: 'Resolved',
  closed: 'Closed',
}

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  const key = (status as IncidentStatus) in STATUS_STYLES ? (status as IncidentStatus) : 'open'
  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border whitespace-nowrap',
        STATUS_STYLES[key],
        className,
      )}
    >
      {STATUS_LABELS[key]}
    </span>
  )
}

function daysUntil(deadline: string): number {
  const ms = new Date(deadline).getTime() - Date.now()
  return Math.ceil(ms / (1000 * 60 * 60 * 24))
}

/** Shows the SLA countdown. Red when breached, muted once the incident is closed/resolved. */
export function SlaCountdown({
  deadline,
  status,
  className,
}: {
  deadline: string | null
  status: string
  className?: string
}) {
  if (!deadline) return <span className={cn('text-xs text-muted', className)}>No SLA</span>

  const days = daysUntil(deadline)
  const settled = status === 'resolved' || status === 'closed'
  const overdue = !settled && days < 0

  const label = overdue
    ? `${Math.abs(days)}d overdue`
    : days === 0
    ? 'Due today'
    : `${days}d left`

  return (
    <span
      className={cn(
        'text-xs font-medium whitespace-nowrap',
        settled ? 'text-muted' : overdue ? 'text-severity-critical' : days <= 2 ? 'text-severity-high' : 'text-muted',
        className,
      )}
    >
      {label}
    </span>
  )
}
