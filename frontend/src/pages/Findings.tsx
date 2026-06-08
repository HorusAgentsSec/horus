import { useEffect, useState } from 'react'
import { ChevronDown, ChevronRight, Boxes } from 'lucide-react'
import { api } from '../lib/api'
import { FindingCard } from '../components/findings/FindingCard'
import { SeverityBadge } from '../components/findings/SeverityBadge'

interface Finding {
  id: string
  title: string
  severity: string
  status: string
  last_seen_at: string
  cve_ids?: string[]
  raw_data?: {
    source_service?: string | null
    exploitability?: string | null
    ssvc?: { priority?: string; label?: string } | null
  }
  assets?: { name: string; host: string }
}

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']
const STATUSES = ['', 'open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk']
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

function worstSeverity(items: Finding[]): string {
  return items.reduce((w, f) => ((SEV_RANK[f.severity] ?? 0) > (SEV_RANK[w] ?? 0) ? f.severity : w), 'info')
}

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')

  const load = () => {
    setLoading(true)
    const params = new URLSearchParams()
    if (severity) params.set('severity', severity)
    if (status) params.set('status', status)
    api.get<Finding[]>(`/findings?${params}`).then((data) => {
      setFindings(data)
      setLoading(false)
    })
  }

  useEffect(load, [severity, status])

  // Findings correlated from a detected service are grouped under it; direct scanner
  // findings (e.g. nmap vulners) stay as standalone rows.
  const groups: Record<string, Finding[]> = {}
  const standalone: Finding[] = []
  for (const f of findings) {
    const svc = f.raw_data?.source_service
    if (svc) (groups[svc] ??= []).push(f)
    else standalone.push(f)
  }

  const select = 'bg-bg border border-border text-sm text-white rounded px-3 py-1.5 focus:outline-none focus:border-accent'

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Findings</h1>
        <div className="flex gap-3">
          <select className={select} value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s || 'All severities'}</option>
            ))}
          </select>
          <select className={select} value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s || 'All statuses'}</option>
            ))}
          </select>
        </div>
      </div>
      {loading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : findings.length === 0 ? (
        <p className="text-muted text-sm">No findings match the current filters.</p>
      ) : (
        <div className="space-y-2">
          {standalone.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
          {Object.entries(groups).map(([service, items]) => (
            <ServiceGroup key={service} service={service} items={items} />
          ))}
        </div>
      )}
    </div>
  )
}

function ServiceGroup({ service, items }: { service: string; items: Finding[] }) {
  const [open, setOpen] = useState(false)
  const active = items.filter((f) => f.raw_data?.exploitability === 'active').length

  return (
    <div className="bg-surface border border-border rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between gap-3 p-4 hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex items-center gap-2 min-w-0">
          {open ? <ChevronDown className="w-4 h-4 text-muted shrink-0" /> : <ChevronRight className="w-4 h-4 text-muted shrink-0" />}
          <Boxes className="w-4 h-4 text-accent shrink-0" />
          <span className="text-sm font-medium text-white truncate">{service}</span>
          <span className="text-xs text-muted shrink-0">
            {items.length} CVE{items.length === 1 ? '' : 's'}
            {active > 0 && <span className="text-severity-critical"> · {active} actively exploited</span>}
          </span>
        </div>
        <SeverityBadge severity={worstSeverity(items)} />
      </button>
      {open && (
        <div className="border-t border-border p-2 space-y-2 bg-bg/30">
          {items.map((f) => (
            <FindingCard key={f.id} finding={f} />
          ))}
        </div>
      )}
    </div>
  )
}
