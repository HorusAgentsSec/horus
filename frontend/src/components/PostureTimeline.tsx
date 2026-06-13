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

// ── Grade system ──────────────────────────────────────────────────────────────

interface Grade {
  letter: string
  label: string
  color: string
  cls: string
}

function scoreToGrade(score: number): Grade {
  if (score < 25)  return { letter: 'A', label: 'excellent',  color: '#22c55e', cls: 'text-green-400' }
  if (score < 100) return { letter: 'B', label: 'good',       color: '#84cc16', cls: 'text-lime-400' }
  if (score < 250) return { letter: 'C', label: 'acceptable', color: '#eab308', cls: 'text-yellow-400' }
  if (score < 500) return { letter: 'D', label: 'poor',       color: '#f97316', cls: 'text-orange-400' }
  return              { letter: 'F', label: 'critical',    color: '#ef4444', cls: 'text-severity-critical' }
}

// Maps raw score (unbounded) to a 0-1 fraction along the gauge arc.
// Each grade band occupies 20% of the arc.
function scoreToFraction(score: number): number {
  if (score < 25)  return (score / 25) * 0.2
  if (score < 100) return 0.2 + ((score - 25) / 75) * 0.2
  if (score < 250) return 0.4 + ((score - 100) / 150) * 0.2
  if (score < 500) return 0.6 + ((score - 250) / 250) * 0.2
  return Math.min(0.8 + (Math.min(score - 500, 500) / 500) * 0.2, 0.97)
}

// ── Gauge SVG ─────────────────────────────────────────────────────────────────
// Semicircle from 9 o'clock (left) through 12 o'clock (top) to 3 o'clock (right).
// sweep-flag=0 on the arc path draws counter-clockwise in SVG (= visually through the top).

function GaugeArc({ score }: { score: number }) {
  const cx = 100
  const cy = 118
  const R = 80
  const SW = 15

  const grade = scoreToGrade(score)
  const f = Math.max(0.02, Math.min(0.97, scoreToFraction(score)))
  const angle = Math.PI * (1 - f)
  const endX = cx + R * Math.cos(angle)
  const endY = cy - R * Math.sin(angle)
  // sweep-flag=1 (clockwise in SVG) goes through the visual top of the circle.
  // large-arc-flag=0 always: we sweep at most 180°.
  const bgPath = `M ${cx - R} ${cy} A ${R} ${R} 0 0 1 ${cx + R} ${cy}`
  const fgPath = `M ${cx - R} ${cy} A ${R} ${R} 0 0 1 ${endX.toFixed(2)} ${endY.toFixed(2)}`

  return (
    <svg viewBox="0 0 200 128" className="w-full" aria-hidden="true">
      {/* Background track */}
      <path
        d={bgPath}
        fill="none"
        stroke="rgba(255,255,255,0.15)"
        strokeWidth={SW}
        strokeDasharray="4 3"
        strokeLinecap="butt"
      />
      {/* Filled arc */}
      <path
        d={fgPath}
        fill="none"
        stroke={grade.color}
        strokeWidth={SW}
        strokeLinecap="round"
      />
      {/* Needle tip — outer glow ring + solid dot */}
      <circle cx={endX} cy={endY} r={13} fill={grade.color} opacity={0.2} />
      <circle cx={endX} cy={endY} r={8} fill={grade.color} />
      {/* Grade letter */}
      <text
        x={cx}
        y={cy - 12}
        textAnchor="middle"
        dominantBaseline="middle"
        fill="white"
        fontSize="56"
        fontWeight="700"
        style={{ fontFamily: 'inherit' }}
      >
        {grade.letter}
      </text>
    </svg>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────

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
  const improving = delta < 0
  const flat = delta === 0
  const TrendIcon = flat ? Minus : improving ? TrendingDown : TrendingUp
  const trendColor = flat ? 'text-muted' : improving ? 'text-mode-auto' : 'text-severity-critical'
  const grade = current ? scoreToGrade(current.risk_score) : null

  return (
    <div className="glass rounded-lg p-6">
      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-horus-lapis" />
          <h2 className="text-sm font-medium text-white uppercase tracking-wider">Security posture</h2>
        </div>
        <div className="flex items-center gap-2">
          {hasHistory && (
            <>
              <button
                type="button"
                onClick={exportPdf}
                disabled={exporting}
                title="Download a board-ready PDF report"
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border border-white/10 text-xs text-white/60 hover:text-white hover:border-white/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {exporting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FileDown className="w-3.5 h-3.5" />}
                {exporting ? 'Exporting…' : 'Export PDF'}
              </button>
              <button
                type="button"
                onClick={emailToBoard}
                disabled={emailing}
                title="Email the report to integrations opted into board reports"
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md border border-white/10 text-xs text-white/60 hover:text-white hover:border-white/30 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {emailing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Mail className="w-3.5 h-3.5" />}
                {emailing ? 'Sending…' : 'Email to board'}
              </button>
            </>
          )}
        </div>
      </div>

      {(exportError || exportOk || emailStatus) && (
        <p className={cn('text-xs mb-3 -mt-3', exportError || (emailStatus && !emailStatus.ok) ? 'text-severity-critical' : 'text-mode-auto')}>
          {exportError ?? (exportOk ? 'PDF downloaded ✓' : emailStatus?.msg)}
        </p>
      )}

      {/* ── Body ────────────────────────────────────────────────────────────── */}
      {loading ? (
        <div className="h-64 flex items-center justify-center text-xs text-white/60">Loading…</div>
      ) : !data || data.timeline.length === 0 ? (
        <div className="h-64 flex flex-col items-center justify-center text-center text-white/60 gap-2">
          <ShieldCheck className="w-8 h-8 opacity-40" />
          <p className="text-sm">No posture history yet.</p>
          <p className="text-xs max-w-sm">
            A snapshot is captured after every scan and once a day. Run a scan to start the timeline.
          </p>
        </div>
      ) : (
        <>
          <div className="flex gap-6 items-start">
            {/* ── Gauge ─────────────────────────────────────────────────────── */}
            {current && grade && (
              <div className="flex flex-col items-center gap-0.5 w-44 shrink-0">
                <GaugeArc score={current.risk_score} />
                <p className="text-[13px] text-center text-white/70 leading-snug mt-1">
                  Security posture{' '}
                  <span className={cn('font-semibold', grade.cls)}>{grade.label}</span>
                </p>
                <div className={cn('flex items-center gap-1 text-[11px] mt-1.5', trendColor)}>
                  <TrendIcon className="w-3 h-3" />
                  <span>
                    {flat
                      ? 'no change'
                      : improving
                      ? `improving ${Math.abs(delta)} pts`
                      : `${delta} pts worse this week`}
                  </span>
                </div>
                {current.kev_active > 0 && (
                  <p className="text-[11px] text-severity-critical mt-1.5">
                    {current.kev_active} actively exploited
                  </p>
                )}
              </div>
            )}

            {/* ── Stacked area chart ─────────────────────────────────────────── */}
            <div className="flex-1 h-64 min-w-0">
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
          </div>

          {/* ── Timeline events ──────────────────────────────────────────────── */}
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

      {/* ── Normalized metrics ───────────────────────────────────────────────── */}
      {normalized && (
        <div className="mt-6 border-t border-white/10 pt-4">
          <p className="text-xs text-muted uppercase font-medium mb-3">Normalized metrics</p>
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
