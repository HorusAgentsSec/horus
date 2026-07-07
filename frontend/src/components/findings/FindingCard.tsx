import { formatDistanceToNow } from 'date-fns'
import { useNavigate } from 'react-router-dom'
import { SeverityBadge } from './SeverityBadge'
import { PriorityBadge } from './PriorityBadge'

interface Finding {
  id: string
  title: string
  severity: string
  status: string
  assets?: { name: string; host: string }
  last_seen_at: string
  raw_data?: { ssvc?: { priority?: string } | null; verdict?: string | null }
}

interface FindingCardProps {
  finding: Finding
  selected?: boolean
  onToggle?: () => void
}

const VERDICT_HINT: Record<string, string> = {
  false_positive: 'Likely false positive',
  needs_verification: 'Needs verification',
}

export function FindingCard({ finding, selected, onToggle }: FindingCardProps) {
  const navigate = useNavigate()

  return (
    <div className="flex items-stretch gap-2">
      {onToggle !== undefined && (
        <div className="flex items-center px-1">
          <input
            type="checkbox"
            checked={selected ?? false}
            onChange={onToggle}
            onClick={(e) => e.stopPropagation()}
            className="w-4 h-4 accent-accent cursor-pointer"
          />
        </div>
      )}
      <div
        className="glass glass-hover rounded-lg p-4 cursor-pointer flex-1 min-w-0"
        onClick={() => onToggle ? onToggle() : navigate(`/findings/${finding.id}`)}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-sm font-medium text-horus-ivory truncate">{finding.title}</p>
            <p className="text-xs text-white/60 mt-1">
              {finding.assets?.name ?? 'Unknown asset'} · {finding.assets?.host}
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <PriorityBadge priority={finding.raw_data?.ssvc?.priority} />
            <SeverityBadge severity={finding.severity} />
          </div>
        </div>
        <div className="flex items-center gap-4 mt-3 text-xs text-white/60">
          <span className="capitalize">{finding.status.replace('_', ' ')}</span>
          <span>Last seen {formatDistanceToNow(new Date(finding.last_seen_at))} ago</span>
          {finding.raw_data?.verdict && VERDICT_HINT[finding.raw_data.verdict] && (
            <span className="text-white/40 italic">{VERDICT_HINT[finding.raw_data.verdict]}</span>
          )}
        </div>
      </div>
    </div>
  )
}
