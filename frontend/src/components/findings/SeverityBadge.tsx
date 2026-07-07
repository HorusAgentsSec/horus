import { cn, severityBg, severityColor } from '../../lib/utils'

interface Props {
  severity: string
  className?: string
}

export function SeverityBadge({ severity, className }: Props) {
  return (
    <span
      className={cn(
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border uppercase tracking-wide',
        severityBg(severity),
        severityColor(severity),
        className,
      )}
    >
      {severity}
    </span>
  )
}
