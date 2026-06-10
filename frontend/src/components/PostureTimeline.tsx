import { useEffect, useState } from 'react'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
} from 'recharts'
import { ShieldCheck, TrendingDown, TrendingUp, Minus, FileDown, Loader2, Mail } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { cn } from '../lib/utils'

interface Point {
  date: string
  risk_score: number
  open_findings: number
  kev_active: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

interface PostureEvent {
  event_date: string
  event_type: string
  description: string
}

interface Timeline {
  timeline: Point[]
  current: Point | null
  trend_delta: number
  events?: PostureEvent[]
}

interface NormalizedMetrics {
  pct_critical_closed_in_7d: number
  open_findings_per_asset: number
  total_critical: number
  closed_critical: number
  fast_closed_critical: number
}

// Stacked from most to least severe (info is noise → omitted from the chart).
const BANDS: { key: keyof Point; label: string; color: string }[] = [
  { key: 'critical', label: 'Critical', color: '#ff4444' },
  { key: 'high', label: 'High', color: '#ff8c00' },
  { key: 'medium', label: 'Medium', color: '#ffd700' },
  { key: 'low', label: 'Low', color: '#58a6ff' },
]

function fmtDate(d: string): string {
  const dt = new Date(d)
  return dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

// The raw score (severity-weighted open findings; critical=10, high=5, KEV +25 each) has no
// intuitive ceiling, so translate it into a band that reads at a glance.
function riskBand(score: number): { label: string; cls: string } {
  if (score < 25) return { label: 'Low', cls: 'text-mode-auto' }
  if (score < 100) return { label: 'Moderate', cls: 'text-severity-medium' }
  if (score < 250) return { label: 'High', cls: 'text-severity-high' }
  return { label: 'Critical', cls: 'text-severity-critical' }
}

export function PostureTimeline({ days = 90 }: { days?: number }) {
  const [data, setData] = useState<Timeline | null>(null)
  const [loading, setLoading] = useState(true)
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const [exportOk, setExportOk] = useState(false)
  const [emailing, setEmailing] = useState(false)
  const [emailStatus, setEmailStatus] = useState<{ msg: string; ok: boolean } | null>(null)
  const [normalized, setNormalized] = useState<NormalizedMetrics | null>(null)

  useEffect(() => {
    setLoading(true)
    api
      .get<Timeline>(`/posture/timeline?days=${days}`)
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [days])

  useEffect(() => {
    api
      .get<NormalizedMetrics>('/posture/normalized')
      .then(setNormalized)
      .catch(() => setNormalized(null))
  }, [])

  const hasHistory = !!data && data.timeline.length > 0

  async function exportPdf() {
    setExporting(true)
    setExportError(null)
    setExportOk(false)
    try {
      await api.download(`/posture/report.pdf?days=${days}`, 'posture-report.pdf')
      setExportOk(true)
      setTimeout(() => setExportOk(false), 3000)
    } catch (err) {
      setExportError(friendlyErrorMessage(err, 'Could not export PDF'))
    } finally {
      setExporting(false)
    }
  }

  async function emailToBoard() {
    setEmailing(true)
    setEmailStatus(null)
    try {
      const res = await api.post<{ sent: number }>(`/posture/report/send?days=${days}`)
      setEmailStatus({ msg: `Sent to ${res.sent} recipient${res.sent === 1 ? '' : 's'} ✓`, ok: true })
    } catch (err) {
      setEmailStatus({ msg: friendlyErrorMessage(err, 'Could not send report'), ok: false })
    } finally {
      setEmailing(false)
    }
  }

  const current = data?.current ?? null
  const delta = data?.trend_delta ?? 0
  // Risk falling (negative delta) is good.
  const improving = delta < 0
  const flat = delta === 0
  const TrendIcon = flat ? Minus : improving ? TrendingDown : TrendingUp
  const trendColor = flat ? 'text-muted' : improving ? 'text-mode-auto' : 'text-severity-critical'

  return (
    <div className="glass rounded-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-horus-lapis" />
          <h2 className="text-sm font-medium text-white uppercase tracking-wider">Security posture</h2>
        </div>
        <div className="flex items-center gap-4 text-sm">
          {current && (
            <>
              <div className="text-right">
                <div className="text-2xl font-semibold text-white leading-none">{current.risk_score}</div>
                <div className="text-[10px] text-white/60 uppercase tracking-wide">risk score</div>
                <div className={cn('text-[10px] uppercase tracking-wide font-semibold', riskBand(current.risk_score).cls)}>
                  {riskBand(current.risk_score).label}
                </div>
              </div>
              <div className={cn('flex items-center gap-1', trendColor)}>
                <TrendIcon className="w-4 h-4" />
                <span className="text-sm font-medium">
                  {flat
                    ? 'no change'
                    : improving
                    ? `${Math.abs(delta)} improving`
                    : `+${delta} worse`}
                </span>
              </div>
            </>
          )}
          {hasHistory && (
            <>
              <button
                type="button"
                onClick={exportPdf}
                disabled={exporting}
                title="Download a board-ready PDF report"
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border border-white/10 text-xs text-white/60 hover:text-white hover:border-white/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {exporting ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <FileDown className="w-3.5 h-3.5" />
                )}
                {exporting ? 'Exporting…' : 'Export PDF'}
              </button>
              <button
                type="button"
                onClick={emailToBoard}
                disabled={emailing}
                title="Email the report to integrations opted into board reports"
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border border-white/10 text-xs text-white/60 hover:text-white hover:border-white/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {emailing ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Mail className="w-3.5 h-3.5" />
                )}
                {emailing ? 'Sending…' : 'Email to board'}
              </button>
            </>
          )}
        </div>
      </div>
      {(exportError || exportOk || emailStatus) && (
        <p
          className={cn(
            'text-xs mb-2 -mt-2',
            exportError || (emailStatus && !emailStatus.ok) ? 'text-severity-critical' : 'text-mode-auto',
          )}
        >
          {exportError ?? (exportOk ? 'PDF downloaded ✓' : emailStatus?.msg)}
        </p>
      )}

      <p className="text-xs text-muted mb-4 -mt-2">
        Lower is better. Severity-weighted open findings over time — the trend you can show your
        board. {improving && !flat && 'Risk is trending down. '}
        {!improving && !flat && 'Risk is trending up — usually new findings or newly discovered assets. '}
      </p>

      {loading ? (
        <div className="h-64 flex items-center justify-center text-xs text-white/60">Loading…</div>
      ) : !data || data.timeline.length === 0 ? (
        <div className="h-64 flex flex-col items-center justify-center text-center text-white/60 gap-2">
          <ShieldCheck className="w-8 h-8 opacity-40" />
          <p className="text-sm">No posture history yet.</p>
          <p className="text-xs max-w-sm">
            A snapshot is captured after every scan and once a day. Run a scan to start the
            timeline.
          </p>
        </div>
      ) : (
        <>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.timeline}>
                <defs>
                  {BANDS.map((b) => (
                    <linearGradient key={b.key} id={`grad-${b.key}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={b.color} stopOpacity={0.5} />
                      <stop offset="95%" stopColor={b.color} stopOpacity={0.05} />
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid stroke="rgba(255,255,255,0.1)" strokeDasharray="3 3" />
                <XAxis dataKey="date" stroke="rgba(255,255,255,0.6)" fontSize={12} tickLine={false} tickFormatter={fmtDate} />
                <YAxis stroke="rgba(255,255,255,0.6)" fontSize={12} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d' }}
                  labelClassName="text-white text-xs font-semibold"
                  labelFormatter={(d) => fmtDate(String(d))}
                  itemStyle={{ fontSize: '12px' }}
                />
                {BANDS.map((b) => (
                  <Area
                    key={b.key}
                    type="monotone"
                    dataKey={b.key}
                    name={b.label}
                    stackId="sev"
                    stroke={b.color}
                    strokeWidth={1.5}
                    fill={`url(#grad-${b.key})`}
                  />
                ))}
                {(data.events ?? []).map((e, i) => (
                  <ReferenceLine
                    key={i}
                    x={e.event_date}
                    stroke="#666"
                    strokeDasharray="3 3"
                    label={{ value: '●', position: 'top', fontSize: 10, fill: '#888' }}
                  />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
          {current && (current.kev_active > 0 || current.open_findings > 0) && (
            <div className="flex items-center gap-4 mt-3 text-xs text-muted">
              <span>{current.open_findings} open findings</span>
              {current.kev_active > 0 && (
                <span className="text-severity-critical">
                  {current.kev_active} actively exploited
                </span>
              )}
            </div>
          )}
          {data.events && data.events.length > 0 && (
            <div className="mt-4 space-y-1">
              <p className="text-xs text-muted uppercase font-medium mb-2">Timeline events</p>
              {data.events.map((e, i) => (
                <div key={i} className="flex gap-2 text-xs">
                  <span className="text-muted">{fmtDate(e.event_date)}</span>
                  <span className="text-white/70">{e.description}</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
      {normalized && (
        <div className="mt-6 border-t border-white/10 pt-4">
          <div className="flex items-start justify-between mb-2">
            <p className="text-xs text-muted uppercase font-medium">Normalized metrics</p>
            <p className="text-[10px] text-white/40 max-w-xs text-right">
              These metrics improve as your team remediates — unlike the raw risk score which rises with more assets.
            </p>
          </div>
          <div className="flex gap-3">
            <div className="flex-1 glass rounded-md p-3">
              {normalized.total_critical === 0 ? (
                <>
                  <div className="text-xl font-semibold leading-none text-white/40">—</div>
                  <div className="text-[10px] text-white/50 mt-1 uppercase tracking-wide">
                    Critical findings closed ≤7d
                  </div>
                  <div className="text-[10px] text-white/40 mt-0.5">No critical findings recorded</div>
                </>
              ) : (
                <>
                  <div className={cn(
                    'text-xl font-semibold leading-none',
                    normalized.pct_critical_closed_in_7d >= 80
                      ? 'text-mode-auto'
                      : normalized.pct_critical_closed_in_7d >= 50
                      ? 'text-yellow-400'
                      : 'text-severity-critical',
                  )}>
                    {normalized.pct_critical_closed_in_7d}%
                  </div>
                  <div className="text-[10px] text-white/50 mt-1 uppercase tracking-wide">
                    Critical findings closed ≤7d
                  </div>
                </>
              )}
            </div>
            <div className="flex-1 glass rounded-md p-3">
              <div className={cn(
                'text-xl font-semibold leading-none',
                normalized.open_findings_per_asset < 2
                  ? 'text-mode-auto'
                  : normalized.open_findings_per_asset < 5
                  ? 'text-yellow-400'
                  : 'text-severity-critical',
              )}>
                {normalized.open_findings_per_asset}
              </div>
              <div className="text-[10px] text-white/50 mt-1 uppercase tracking-wide">
                Open findings per asset
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
