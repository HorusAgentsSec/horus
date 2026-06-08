import { cn } from '../../lib/utils'

// SSVC deployer priority. Severity says "how bad is the bug"; this says "what should we do" given
// how exploited it is and how exposed we are. Act > Attend > Track* > Track.
const STYLES: Record<string, { label: string; cls: string; title: string }> = {
  act: { label: 'Act', cls: 'bg-severity-critical/15 text-severity-critical border-severity-critical/30', title: 'Act now — exploited and exposed' },
  attend: { label: 'Attend', cls: 'bg-severity-high/15 text-severity-high border-severity-high/30', title: 'Attend soon — schedule remediation' },
  track_star: { label: 'Track*', cls: 'bg-accent/15 text-accent border-accent/30', title: 'Track closely — revisit if exposure or impact changes' },
  track: { label: 'Track', cls: 'bg-white/5 text-muted border-border', title: 'Track — no action required yet' },
}

export function PriorityBadge({ priority }: { priority?: string | null }) {
  if (!priority) return null
  const s = STYLES[priority]
  if (!s) return null
  return (
    <span
      title={s.title}
      className={cn('text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded border', s.cls)}
    >
      {s.label}
    </span>
  )
}
