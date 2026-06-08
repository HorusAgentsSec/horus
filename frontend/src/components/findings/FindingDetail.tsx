import { Swords } from 'lucide-react'
import { SeverityBadge } from './SeverityBadge'
import { PriorityBadge } from './PriorityBadge'
import { VerdictBadge } from './VerdictBadge'
import { SuggestionCard } from '../agents/SuggestionCard'
import { cn, modeBadgeColor } from '../../lib/utils'

interface Suggestion {
  id: string
  action_type: string
  title: string
  description: string
  command_or_patch: string | null
  confidence_score: number
  estimated_risk: string
  mode: string
  status: string
}

interface Finding {
  id: string
  title: string
  description: string
  severity: string
  cvss_score: number | null
  cve_ids: string[]
  status: string
  raw_data: {
    threat_context?: string
    exploitability?: string
    confidence?: number
    verdict?: string
    verdict_rationale?: string
    debate?: { red?: string; blue?: string } | null
    ssvc?: {
      priority?: string
      label?: string
      rationale?: string
      exploitation?: string
      exposure?: string
      automatable?: boolean
      technical_impact?: string
    } | null
  }
  first_seen_at: string
  last_seen_at: string
  assets?: { name: string; host: string }
}

interface Props {
  finding: Finding
  suggestions: Suggestion[]
  onApprove: (id: string) => void
  onReject: (id: string) => void
}

export function FindingDetailView({ finding, suggestions, onApprove, onReject }: Props) {
  return (
    <div className="space-y-6">
      <div className="bg-surface border border-border rounded-lg p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-lg font-semibold text-white">{finding.title}</h1>
            <p className="text-sm text-muted mt-1">
              {finding.assets?.name} ({finding.assets?.host})
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <VerdictBadge verdict={finding.raw_data.verdict} />
            <PriorityBadge priority={finding.raw_data.ssvc?.priority} />
            <SeverityBadge severity={finding.severity} />
          </div>
        </div>

        {finding.cvss_score && (
          <p className="text-xs text-muted mt-3">CVSS {finding.cvss_score}</p>
        )}

        {finding.cve_ids.length > 0 && (
          <div className="flex flex-wrap gap-2 mt-3">
            {finding.cve_ids.map((cve) => (
              <a
                key={cve}
                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                target="_blank"
                rel="noreferrer"
                className="text-xs text-accent hover:underline"
              >
                {cve}
              </a>
            ))}
          </div>
        )}

        <p className="text-sm text-white/80 mt-4 leading-relaxed">{finding.description}</p>

        {finding.raw_data.threat_context && (
          <div className="mt-4 p-3 bg-bg rounded border border-border">
            <p className="text-xs font-medium text-muted uppercase mb-1">Threat Intelligence</p>
            <p className="text-sm text-white/80">{finding.raw_data.threat_context}</p>
            {finding.raw_data.exploitability && (
              <p className="text-xs text-muted mt-2">
                Exploitability:{' '}
                <span className="text-white">{finding.raw_data.exploitability}</span>
              </p>
            )}
          </div>
        )}

        {/* Red/blue validation debate — how the verdict was reached. */}
        {finding.raw_data.debate && (finding.raw_data.debate.red || finding.raw_data.debate.blue) && (
          <div className="mt-4 p-3 bg-bg rounded border border-border">
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs font-medium text-muted uppercase flex items-center gap-1.5">
                <Swords className="w-3.5 h-3.5" /> Validation debate
              </p>
              <VerdictBadge verdict={finding.raw_data.verdict} />
            </div>
            <div className="grid sm:grid-cols-2 gap-3">
              <div className="p-2 rounded border border-severity-critical/20 bg-severity-critical/[0.04]">
                <p className="text-[10px] font-semibold uppercase tracking-wide text-severity-critical mb-1">Red team — why it's real</p>
                <p className="text-xs text-white/80 leading-relaxed">{finding.raw_data.debate.red || '—'}</p>
              </div>
              <div className="p-2 rounded border border-mode-auto/20 bg-mode-auto/[0.04]">
                <p className="text-[10px] font-semibold uppercase tracking-wide text-mode-auto mb-1">Blue team — why it's not</p>
                <p className="text-xs text-white/80 leading-relaxed">{finding.raw_data.debate.blue || '—'}</p>
              </div>
            </div>
            {finding.raw_data.verdict_rationale && (
              <p className="text-xs text-muted mt-2">
                Judge: <span className="text-white/80">{finding.raw_data.verdict_rationale}</span>
                {typeof finding.raw_data.confidence === 'number' && (
                  <span> · confidence {Math.round(finding.raw_data.confidence * 100)}%</span>
                )}
              </p>
            )}
          </div>
        )}

        {/* Verdict reached without a debate (recalled from team memory, KEV-active, or auto). */}
        {finding.raw_data.verdict && finding.raw_data.verdict_rationale && !finding.raw_data.debate && (
          <div className="mt-4 p-3 bg-bg rounded border border-border flex items-center justify-between gap-3">
            <p className="text-xs text-white/80">
              <span className="text-muted uppercase font-medium">Validation</span>{' '}
              {finding.raw_data.verdict_rationale}
            </p>
            <VerdictBadge verdict={finding.raw_data.verdict} />
          </div>
        )}

        {/* SSVC deployer decision — the contextual priority and how it was derived. */}
        {finding.raw_data.ssvc?.priority && (
          <div className="mt-4 p-3 bg-bg rounded border border-border">
            <div className="flex items-center justify-between mb-1">
              <p className="text-xs font-medium text-muted uppercase">SSVC priority</p>
              <PriorityBadge priority={finding.raw_data.ssvc.priority} />
            </div>
            {finding.raw_data.ssvc.rationale && (
              <p className="text-sm text-white/80">{finding.raw_data.ssvc.rationale}.</p>
            )}
            <p className="text-xs text-muted mt-2">
              Exploitation <span className="text-white">{finding.raw_data.ssvc.exploitation}</span>
              {' · '}Exposure <span className="text-white">{finding.raw_data.ssvc.exposure}</span>
              {' · '}Automatable <span className="text-white">{finding.raw_data.ssvc.automatable ? 'yes' : 'no'}</span>
              {' · '}Impact <span className="text-white">{finding.raw_data.ssvc.technical_impact}</span>
            </p>
          </div>
        )}
      </div>

      {suggestions.length > 0 && (
        <div>
          <h2 className="text-sm font-medium text-muted uppercase mb-3">AI Suggestions</h2>
          <div className="space-y-3">
            {suggestions.map((s) => (
              <SuggestionCard
                key={s.id}
                suggestion={s}
                onApprove={() => onApprove(s.id)}
                onReject={() => onReject(s.id)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
