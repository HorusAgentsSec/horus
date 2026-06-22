import { useEffect, useRef, useState } from 'react'
import { ChevronDown, ChevronRight, Boxes, Download, Upload } from 'lucide-react'
import { api, exportApi, friendlyErrorMessage } from '../lib/api'
import { useAssets } from '../hooks/useAssets'
import { FindingCard } from '../components/findings/FindingCard'
import { SeverityBadge } from '../components/findings/SeverityBadge'
import { ImportModal } from '../components/ImportModal'

interface Finding {
  id: string
  title: string
  severity: string
  status: string
  last_seen_at: string
  cve_ids?: string[]
  is_noise?: boolean
  raw_data?: {
    source_service?: string | null
    exploitability?: string | null
    ssvc?: { priority?: string; label?: string } | null
  }
  assets?: { name: string; host: string }
}

interface FindingsResponse {
  items: Finding[]
  noise_count: number
}

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']
const STATUSES = ['', 'open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk']
const TOOLS = ['', 'nmap', 'nuclei']
const ORDER_OPTIONS = [
  { value: '', label: 'Newest first' },
  { value: 'severity', label: 'Severity' },
]
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

function worstSeverity(items: Finding[]): string {
  return items.reduce((w, f) => ((SEV_RANK[f.severity] ?? 0) > (SEV_RANK[w] ?? 0) ? f.severity : w), 'info')
}

const BULK_ACTIONS = [
  { action: 'mark_false_positive', label: 'Mark False Positive' },
  { action: 'accept_risk', label: 'Accept Risk' },
  { action: 'mark_resolved', label: 'Mark Resolved' },
  { action: 'mark_open', label: 'Mark Open' },
]

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [assetId, setAssetId] = useState('')
  const [cveInput, setCveInput] = useState('')
  const [cveFilter, setCveFilter] = useState('')
  const [tool, setTool] = useState('')
  const [orderBy, setOrderBy] = useState('')
  // "No X found" / scanner-noise findings are hidden by default; the banner toggles them.
  const [showNoise, setShowNoise] = useState(false)
  const [noiseCount, setNoiseCount] = useState(0)

  // Bulk selection
  const [selecting, setSelecting] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // Import modal
  const [showImport, setShowImport] = useState(false)

  const { assets } = useAssets()

  const load = () => {
    setLoading(true)
    setLoadError('')
    const params = new URLSearchParams()
    if (severity) params.set('severity', severity)
    if (status) params.set('status', status)
    if (assetId) params.set('asset_id', assetId)
    if (cveFilter) params.set('cve_id', cveFilter)
    if (tool) params.set('tool', tool)
    if (orderBy) params.set('order_by', orderBy)
    if (showNoise) params.set('include_noise', 'true')
    api
      .get<FindingsResponse>(`/findings?${params}`)
      .then((data) => {
        setFindings(data.items)
        setNoiseCount(data.noise_count)
        setLoading(false)
      })
      .catch((e) => {
        setLoadError(friendlyErrorMessage(e, 'Could not load findings'))
        setLoading(false)
      })
  }

  useEffect(load, [severity, status, assetId, cveFilter, tool, orderBy, showNoise])

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const handleBulkAction = async (action: string) => {
    if (selectedIds.size === 0) return
    await api.post('/findings/bulk', { ids: Array.from(selectedIds), action })
    setSelectedIds(new Set())
    setSelecting(false)
    load()
  }

  const clearSelection = () => {
    setSelectedIds(new Set())
    setSelecting(false)
  }

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
  const inputCls = 'bg-bg border border-border text-sm text-white rounded px-3 py-1.5 focus:outline-none focus:border-accent placeholder-white/30 w-36'

  return (
    <div className="space-y-6">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Findings</h1>
        <button
          onClick={() => { setSelecting((s) => !s); setSelectedIds(new Set()) }}
          className={`text-sm px-3 py-1.5 rounded border transition-colors ${selecting ? 'bg-accent/20 border-accent text-accent' : 'border-border text-muted hover:border-white/40'}`}
        >
          {selecting ? 'Cancel' : 'Select'}
        </button>
      </div>

      <ImportModal open={showImport} onClose={() => setShowImport(false)} onSuccess={load} />

      {/* Filter rows */}
      <div className="flex flex-wrap gap-3 items-center">
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
        <select className={select} value={assetId} onChange={(e) => setAssetId(e.target.value)}>
          <option value="">All assets</option>
          {assets.map((a) => (
            <option key={a.id} value={a.id}>{a.name}</option>
          ))}
        </select>
        <input
          type="text"
          className={inputCls}
          placeholder="CVE-2024-…"
          value={cveInput}
          onChange={(e) => setCveInput(e.target.value)}
          onBlur={() => setCveFilter(cveInput.trim())}
          onKeyDown={(e) => { if (e.key === 'Enter') setCveFilter(cveInput.trim()) }}
        />
        <select className={select} value={tool} onChange={(e) => setTool(e.target.value)}>
          {TOOLS.map((t) => (
            <option key={t} value={t}>{t || 'All tools'}</option>
          ))}
        </select>
        <select className={select} value={orderBy} onChange={(e) => setOrderBy(e.target.value)}>
          {ORDER_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
        <div className="ml-auto flex gap-2">
          <button
            onClick={() => setShowImport(true)}
            className="text-xs px-3 py-1.5 rounded border border-border text-muted hover:text-white hover:border-white/40 transition-colors flex items-center gap-1.5"
          >
            <Upload className="w-3.5 h-3.5" />
            Import
          </button>
          <button
            onClick={() => exportApi.exportJsonl(showNoise)}
            className="text-xs px-3 py-1.5 rounded border border-border text-muted hover:text-white hover:border-white/40 transition-colors flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            JSONL
          </button>
          <button
            onClick={() => exportApi.exportCsv(showNoise)}
            className="text-xs px-3 py-1.5 rounded border border-border text-muted hover:text-white hover:border-white/40 transition-colors flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            CSV
          </button>
        </div>
      </div>

      {/* Bulk action bar */}
      {selecting && selectedIds.size > 0 && (
        <div className="sticky top-0 z-10 flex flex-wrap items-center gap-3 bg-surface border border-border rounded-lg px-4 py-3">
          <span className="text-sm text-muted">{selectedIds.size} selected</span>
          {BULK_ACTIONS.map((ba) => (
            <button
              key={ba.action}
              onClick={() => handleBulkAction(ba.action)}
              className="text-xs px-3 py-1.5 rounded border border-border hover:border-accent hover:text-accent transition-colors"
            >
              {ba.label}
            </button>
          ))}
          <button
            onClick={clearSelection}
            className="text-xs px-3 py-1.5 rounded border border-border text-muted hover:text-white transition-colors ml-auto"
          >
            Clear
          </button>
        </div>
      )}

      {/* Noise banner: absence-of-finding results ("No XSS found…") are hidden by default */}
      {!loading && noiseCount > 0 && (
        <div className="flex items-center gap-2 text-xs text-muted border border-border/60 rounded-lg px-4 py-2.5 bg-surface/50">
          <span>
            {showNoise
              ? `Showing ${noiseCount} informational/absence result${noiseCount === 1 ? '' : 's'}.`
              : `${noiseCount} informational/absence result${noiseCount === 1 ? '' : 's'} hidden.`}
          </span>
          <button
            onClick={() => setShowNoise((s) => !s)}
            className="text-accent hover:underline"
          >
            {showNoise ? 'Hide' : 'Show'}
          </button>
        </div>
      )}

      {loading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : loadError ? (
        <p className="text-sm text-severity-critical">{loadError}</p>
      ) : findings.length === 0 ? (
        <p className="text-muted text-sm">No findings match the current filters.</p>
      ) : (
        <div className="stagger space-y-2">
          {standalone.map((f) => (
            <FindingCard
              key={f.id}
              finding={f}
              selected={selecting ? selectedIds.has(f.id) : undefined}
              onToggle={selecting ? () => toggleSelect(f.id) : undefined}
            />
          ))}
          {Object.entries(groups).map(([service, items]) => (
            <ServiceGroup
              key={service}
              service={service}
              items={items}
              selecting={selecting}
              selectedIds={selectedIds}
              onToggle={toggleSelect}
            />
          ))}
        </div>
      )}
    </div>
  )
}

interface ServiceGroupProps {
  service: string
  items: Finding[]
  selecting: boolean
  selectedIds: Set<string>
  onToggle: (id: string) => void
}

function ServiceGroup({ service, items, selecting, selectedIds, onToggle }: ServiceGroupProps) {
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
            <FindingCard
              key={f.id}
              finding={f}
              selected={selecting ? selectedIds.has(f.id) : undefined}
              onToggle={selecting ? () => onToggle(f.id) : undefined}
            />
          ))}
        </div>
      )}
    </div>
  )
}
