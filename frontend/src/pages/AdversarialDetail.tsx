import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Swords, Shield, Terminal, ExternalLink,
  ChevronDown, ChevronRight, CheckCircle, XCircle, Clock, Trash2,
} from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { SeverityBadge } from '../components/findings/SeverityBadge'
import { cn, severityColor, severityBg } from '../lib/utils'
import { useRole } from '../hooks/useRole'
import type { RedFinding } from '../components/adversarial/RedFindingCard'

interface BlueResponse {
  summary: string
  remediation_steps: string[]
  config_snippet?: string
  verification?: string
  effort?: string
  references?: string[]
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

const EFFORT_COLOR: Record<string, string> = {
  minutes: 'text-mode-auto',
  hours:   'text-severity-medium',
  days:    'text-severity-high',
}

export default function AdversarialDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { can } = useRole()

  const [finding, setFinding] = useState<RedFinding | null>(null)
  const [loading, setLoading]   = useState(true)
  const [saving, setSaving]     = useState(false)
  const [error, setError]       = useState('')
  const [evidenceOpen, setEvidenceOpen] = useState(false)

  const load = async () => {
    if (!id) return
    try {
      const data = await api.get<RedFinding>(`/adversarial/findings/${id}`)
      setFinding(data)
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Failed to load finding'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [id])

  const updateStatus = async (status: string) => {
    if (!id) return
    setSaving(true)
    try {
      const updated = await api.patch<RedFinding>(`/adversarial/findings/${id}`, { status })
      setFinding(updated)
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Failed to update status'))
    } finally {
      setSaving(false)
    }
  }

  const deleteFinding = async () => {
    if (!id || !window.confirm('Delete this finding permanently? This cannot be undone.')) return
    setSaving(true)
    try {
      await api.delete(`/adversarial/findings/${id}`)
      navigate('/adversarial')
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Failed to delete finding'))
      setSaving(false)
    }
  }

  if (loading) return <p className="text-muted text-sm">Loading…</p>
  if (error)   return <p className="text-severity-critical text-sm">{error}</p>
  if (!finding) return null

  const blue = finding.blue_response as BlueResponse | null | undefined

  return (
    <div className="max-w-3xl space-y-6">

      {/* ── Back ──────────────────────────────────────────────────────────── */}
      <button
        onClick={() => navigate('/adversarial')}
        className="flex items-center gap-2 text-sm text-muted hover:text-white transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Red / Blue Agents
      </button>

      {/* ── Header card ───────────────────────────────────────────────────── */}
      <div className="glass rounded-lg p-6 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <Swords className="w-5 h-5 text-horus-gold shrink-0 mt-0.5" />
            <h1 className="text-lg font-semibold leading-snug">{finding.title}</h1>
          </div>
          <div className="flex items-center gap-2 shrink-0 flex-wrap justify-end">
            <span className={cn('text-xs px-2 py-0.5 rounded border capitalize', CATEGORY_STYLES[finding.category] ?? CATEGORY_STYLES.other)}>
              {finding.category.replace('_', ' ')}
            </span>
            <SeverityBadge severity={finding.severity} />
            <span className={cn('text-xs px-2 py-0.5 rounded border capitalize', STATUS_STYLES[finding.status] ?? STATUS_STYLES.open)}>
              {finding.status.replace('_', ' ')}
            </span>
          </div>
        </div>

        {finding.assets && (
          <p className="text-xs text-white/50">
            Asset: <span className="text-white/70">{finding.assets.name}</span> · {finding.assets.host}
          </p>
        )}

        {/* Description */}
        <div>
          <h2 className="text-xs text-muted uppercase tracking-wide mb-2">Description</h2>
          <p className="text-sm text-white/80 leading-relaxed">{finding.description}</p>
        </div>

        {/* Attack scenario */}
        {finding.attack_scenario && (
          <div>
            <h2 className="text-xs text-muted uppercase tracking-wide mb-2">Attack Scenario</h2>
            <div className="bg-severity-critical/5 border border-severity-critical/20 rounded-md p-4">
              <p className="text-sm text-white/80 leading-relaxed">{finding.attack_scenario}</p>
            </div>
          </div>
        )}

        {/* Evidence (collapsible) */}
        {finding.evidence && Object.keys(finding.evidence).length > 0 && (
          <div>
            <button
              className="flex items-center gap-1.5 text-xs text-muted hover:text-white transition-colors mb-2"
              onClick={() => setEvidenceOpen((o) => !o)}
            >
              {evidenceOpen ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              Raw evidence
            </button>
            {evidenceOpen && (
              <pre className="bg-bg border border-border rounded-md p-4 text-xs text-white/60 overflow-x-auto">
                {JSON.stringify(finding.evidence, null, 2)}
              </pre>
            )}
          </div>
        )}
      </div>

      {/* ── Blue response ─────────────────────────────────────────────────── */}
      {blue ? (
        <div className="glass rounded-lg p-6 space-y-5">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-mode-auto" />
            <h2 className="text-sm font-semibold text-mode-auto">Blue Team Response</h2>
            {blue.effort && (
              <span className={cn('text-xs ml-auto', EFFORT_COLOR[blue.effort] ?? 'text-muted')}>
                <Clock className="inline w-3 h-3 mr-1" />
                est. {blue.effort}
              </span>
            )}
          </div>

          <div>
            <h3 className="text-xs text-muted uppercase tracking-wide mb-2">Root Cause</h3>
            <p className="text-sm text-white/80 leading-relaxed">{blue.summary}</p>
          </div>

          <div>
            <h3 className="text-xs text-muted uppercase tracking-wide mb-3">Remediation Steps</h3>
            <ol className="space-y-2">
              {blue.remediation_steps.map((step, i) => (
                <li key={i} className="flex gap-3 text-sm text-white/80">
                  <span className="shrink-0 w-5 h-5 rounded-full bg-horus-lapis/30 text-accent text-xs flex items-center justify-center font-medium">
                    {i + 1}
                  </span>
                  <span className="leading-relaxed">{step}</span>
                </li>
              ))}
            </ol>
          </div>

          {blue.config_snippet && (
            <div>
              <h3 className="text-xs text-muted uppercase tracking-wide mb-2">Config / Command</h3>
              <div className="bg-bg border border-border rounded-md p-4 flex gap-2">
                <Terminal className="w-3.5 h-3.5 text-muted shrink-0 mt-0.5" />
                <pre className="text-xs text-white/80 overflow-x-auto whitespace-pre-wrap">{blue.config_snippet}</pre>
              </div>
            </div>
          )}

          {blue.verification && (
            <div>
              <h3 className="text-xs text-muted uppercase tracking-wide mb-2">Verification</h3>
              <div className="bg-mode-auto/5 border border-mode-auto/20 rounded-md p-3">
                <p className="text-sm text-white/80">{blue.verification}</p>
              </div>
            </div>
          )}

          {blue.references && blue.references.length > 0 && (
            <div>
              <h3 className="text-xs text-muted uppercase tracking-wide mb-2">References</h3>
              <ul className="space-y-1">
                {blue.references.map((ref, i) => (
                  <li key={i}>
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1.5 text-xs text-accent hover:underline"
                    >
                      <ExternalLink className="w-3 h-3" />
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : finding.status === 'open' ? (
        <div className="glass rounded-lg p-6 text-center">
          <Shield className="w-6 h-6 text-white/20 mx-auto mb-2" />
          <p className="text-sm text-white/40">Blue agent hasn't responded to this finding yet.</p>
          <p className="text-xs text-white/30 mt-1">
            Responses are generated automatically after each Red→Blue cycle.
          </p>
        </div>
      ) : null}

      {/* ── Actions ───────────────────────────────────────────────────────── */}
      {can('analyst') && (
        <div className="flex flex-wrap gap-3 items-center">
          {finding.status !== 'accepted' && finding.status !== 'false_positive' && (
            <>
              <button
                disabled={saving}
                onClick={() => updateStatus('accepted')}
                className="flex items-center gap-2 px-4 py-2 rounded-md bg-mode-auto/10 text-mode-auto border border-mode-auto/30 text-sm hover:bg-mode-auto/20 disabled:opacity-50 transition-colors"
              >
                <CheckCircle className="w-4 h-4" />
                Accept risk
              </button>
              <button
                disabled={saving}
                onClick={() => updateStatus('false_positive')}
                className="flex items-center gap-2 px-4 py-2 rounded-md bg-surface text-muted border border-border text-sm hover:text-white hover:border-white/20 disabled:opacity-50 transition-colors"
              >
                <XCircle className="w-4 h-4" />
                False positive
              </button>
            </>
          )}
          <button
            disabled={saving}
            onClick={deleteFinding}
            className="flex items-center gap-2 px-4 py-2 rounded-md bg-severity-critical/10 text-severity-critical border border-severity-critical/30 text-sm hover:bg-severity-critical/20 disabled:opacity-50 transition-colors ml-auto"
          >
            <Trash2 className="w-4 h-4" />
            Delete
          </button>
        </div>
      )}
    </div>
  )
}
