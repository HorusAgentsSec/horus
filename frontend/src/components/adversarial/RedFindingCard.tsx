import { useNavigate } from 'react-router-dom'
import { ShieldAlert, ShieldCheck, CheckCircle, XCircle, ChevronRight } from 'lucide-react'
import { cn, severityColor, severityBg } from '../../lib/utils'

export interface RedFinding {
  id: string
  title: string
  description: string
  attack_scenario?: string
  severity: string
  category: string
  status: string
  evidence?: Record<string, unknown> | null
  blue_response?: Record<string, unknown> | null
  created_at: string
  assets?: { name: string; host: string }
}

const CATEGORY_STYLES: Record<string, string> = {
  dns:           'bg-horus-turquoise/10 text-horus-turquoise border-horus-turquoise/30',
  ssl:           'bg-severity-medium/10 text-severity-medium border-severity-medium/30',
  headers:       'bg-severity-high/10 text-severity-high border-severity-high/30',
  exposed_path:  'bg-severity-critical/10 text-severity-critical border-severity-critical/30',
  subdomain:     'bg-horus-lapis/20 text-accent border-accent/30',
  breach:        'bg-severity-critical/10 text-severity-critical border-severity-critical/30',
  exploit:       'bg-severity-high/10 text-severity-high border-severity-high/30',
  network:       'bg-accent/10 text-accent border-accent/30',
  other:         'bg-surface text-muted border-border',
}

const STATUS_STYLES: Record<string, string> = {
  open:           'bg-accent/10 text-accent border-accent/30',
  responded:      'bg-mode-auto/10 text-mode-auto border-mode-auto/30',
  accepted:       'bg-surface text-muted border-border',
  false_positive: 'bg-surface text-muted border-border',
}

const STATUS_ICONS: Record<string, React.ElementType> = {
  open:           ShieldAlert,
  responded:      ShieldCheck,
  accepted:       CheckCircle,
  false_positive: XCircle,
}

export function RedFindingCard({ finding }: { finding: RedFinding }) {
  const navigate = useNavigate()
  const StatusIcon = STATUS_ICONS[finding.status] ?? ShieldAlert

  return (
    <div
      className="glass glass-hover rounded-lg p-4 cursor-pointer"
      onClick={() => navigate(`/adversarial/${finding.id}`)}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <StatusIcon className={cn('w-3.5 h-3.5 shrink-0', STATUS_STYLES[finding.status]?.split(' ')[1] ?? 'text-muted')} />
            <p className="text-sm font-medium text-horus-ivory truncate">{finding.title}</p>
          </div>
          {finding.assets && (
            <p className="text-xs text-white/50 mb-2">
              {finding.assets.name} · {finding.assets.host}
            </p>
          )}
          {finding.attack_scenario && (
            <p className="text-xs text-white/60 line-clamp-2">{finding.attack_scenario}</p>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className={cn('text-xs px-2 py-0.5 rounded border capitalize', CATEGORY_STYLES[finding.category] ?? CATEGORY_STYLES.other)}>
            {finding.category.replace('_', ' ')}
          </span>
          <span className={cn('text-xs px-2 py-0.5 rounded border uppercase font-medium', severityBg(finding.severity), severityColor(finding.severity))}>
            {finding.severity}
          </span>
          <span className={cn('text-xs px-2 py-0.5 rounded border capitalize', STATUS_STYLES[finding.status] ?? STATUS_STYLES.open)}>
            {finding.status.replace('_', ' ')}
          </span>
          <ChevronRight className="w-4 h-4 text-white/30" />
        </div>
      </div>
    </div>
  )
}
