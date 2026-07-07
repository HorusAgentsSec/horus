import { ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { cn } from '../../lib/utils'

// The red/blue debate verdict. Mirrors backend core.validation.VERDICTS.
export const VERDICTS: Record<string, { label: string; cls: string; Icon: typeof ShieldCheck }> = {
  confirmed: { label: 'Confirmed', cls: 'bg-severity-high/15 text-severity-high border-severity-high/30', Icon: ShieldAlert },
  likely: { label: 'Likely real', cls: 'bg-accent/15 text-accent border-accent/30', Icon: ShieldAlert },
  needs_verification: { label: 'Needs verification', cls: 'bg-white/5 text-muted border-border', Icon: ShieldQuestion },
  false_positive: { label: 'Likely false positive', cls: 'bg-mode-auto/15 text-mode-auto border-mode-auto/30', Icon: ShieldCheck },
}

export function VerdictBadge({ verdict }: { verdict?: string | null }) {
  if (!verdict || !VERDICTS[verdict]) return null
  const { label, cls, Icon } = VERDICTS[verdict]
  return (
    <span className={cn('inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded border', cls)}>
      <Icon className="w-3 h-3" /> {label}
    </span>
  )
}
