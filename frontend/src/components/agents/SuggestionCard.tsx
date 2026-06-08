import { Check, X, Terminal, ShieldAlert } from 'lucide-react'
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
  safety_tier?: string | null
  status: string
}

const MODE_LABEL: Record<string, string> = {
  auto: 'AUTO',
  approval_required: 'APPROVAL',
  suggest_only: 'SUGGEST',
}

// Blast-radius tier — the hard ceiling on auto-execution.
const SAFETY: Record<string, { label: string; cls: string }> = {
  reversible: { label: 'Reversible', cls: 'text-mode-auto border-mode-auto/40' },
  disruptive: { label: 'Disruptive', cls: 'text-severity-medium border-severity-medium/40' },
  destructive: { label: 'Destructive', cls: 'text-severity-critical border-severity-critical/40' },
}

export function SuggestionCard({
  suggestion,
  onApprove,
  onReject,
}: {
  suggestion: Suggestion
  onApprove: () => void
  onReject: () => void
}) {
  const isPending = suggestion.status === 'pending'

  return (
    <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-medium text-white">{suggestion.title}</p>
          <p className="text-xs text-muted mt-0.5 capitalize">{suggestion.action_type.replace(/_/g, ' ')}</p>
        </div>
        <span
          className={cn(
            'shrink-0 text-xs px-2 py-0.5 rounded border font-mono',
            modeBadgeColor(suggestion.mode),
          )}
        >
          {MODE_LABEL[suggestion.mode] ?? suggestion.mode}
        </span>
      </div>

      <p className="text-sm text-white/70 leading-relaxed">{suggestion.description}</p>

      {suggestion.command_or_patch && (
        <div className="bg-bg rounded p-3 border border-border flex gap-2">
          <Terminal className="w-3.5 h-3.5 text-muted shrink-0 mt-0.5" />
          <pre className="text-xs text-white/80 overflow-x-auto whitespace-pre-wrap font-mono">
            {suggestion.command_or_patch}
          </pre>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div className="flex gap-4 text-xs text-muted">
          <span>Confidence {Math.round(suggestion.confidence_score * 100)}%</span>
          <span>
            Fix risk:{' '}
            <span
              className={cn(
                suggestion.estimated_risk === 'high'
                  ? 'text-severity-high'
                  : suggestion.estimated_risk === 'medium'
                  ? 'text-severity-medium'
                  : 'text-mode-auto',
              )}
            >
              {suggestion.estimated_risk}
            </span>
          </span>
        </div>

        {isPending && (
          <div className="flex gap-2">
            <button
              onClick={onReject}
              className="flex items-center gap-1 text-xs text-muted hover:text-severity-critical border border-border hover:border-severity-critical/40 px-3 py-1 rounded transition-colors"
            >
              <X className="w-3 h-3" /> Reject
            </button>
            <button
              onClick={onApprove}
              className="flex items-center gap-1 text-xs text-white hover:text-mode-auto border border-border hover:border-mode-auto/60 px-3 py-1 rounded transition-colors"
            >
              <Check className="w-3 h-3" /> Approve
            </button>
          </div>
        )}

        {!isPending && (
          <span
            className={cn(
              'text-xs px-2 py-0.5 rounded',
              suggestion.status === 'approved' ? 'text-mode-auto' : 'text-muted',
            )}
          >
            {suggestion.status}
          </span>
        )}
      </div>
    </div>
  )
}
