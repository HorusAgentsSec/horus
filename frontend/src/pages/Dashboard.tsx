import { useEffect, useState, useCallback } from 'react'
import {
  AlertTriangle,
  Shield,
  Target,
  Clock,
  TrendingDown,
  TrendingUp,
  Minus,
  Settings2,
  X,
  Server,
  Eye,
  CheckCircle2,
  ChevronRight,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { formatDistanceToNow } from 'date-fns'
import { api } from '../lib/api'
import { FindingCard } from '../components/findings/FindingCard'
import { PostureTimeline } from '../components/PostureTimeline'
import { useRealtime } from '../hooks/useRealtime'
import { supabase } from '../lib/supabase'
import { cn } from '../lib/utils'

// ── Types ─────────────────────────────────────────────────────────────────────

interface DashboardStats {
  total_assets: number
  open_findings_by_severity: Record<string, number>
  recent_scans: { id: string; status: string; created_at: string; assets: { name: string } }[]
  pending_suggestions: number
}

interface DashboardMetrics {
  ssvc: { act: number; attend: number; track_star: number; track: number; none: number }
  kev_active: number
  asset_coverage: { scanned: number; total: number; pct: number }
  findings_trend: { new_this_week: number; new_prev_week: number; resolved_this_week: number }
  mttr_critical_days: number | null
  top_risky_assets: { id: string; name: string; critical: number; high: number; act: number }[]
  open_by_severity: { critical: number; high: number; medium: number; low: number }
}

type WidgetId =
  | 'act_now'
  | 'kev_exposure'
  | 'asset_coverage'
  | 'mttr'
  | 'findings_trend'
  | 'open_severity'
  | 'ssvc_breakdown'
  | 'posture_chart'
  | 'top_assets'
  | 'recent_scans'
  | 'recent_findings'

interface WidgetMeta {
  id: WidgetId
  label: string
  section: 'primary' | 'secondary' | 'bottom'
}

// ── Widget config ─────────────────────────────────────────────────────────────

const ALL_WIDGETS: WidgetMeta[] = [
  { id: 'act_now', label: 'Act Now', section: 'primary' },
  { id: 'kev_exposure', label: 'KEV Exposure', section: 'primary' },
  { id: 'asset_coverage', label: 'Asset Coverage', section: 'primary' },
  { id: 'mttr', label: 'MTTR Critical', section: 'primary' },
  { id: 'findings_trend', label: 'Findings Trend', section: 'secondary' },
  { id: 'open_severity', label: 'Open by Severity', section: 'secondary' },
  { id: 'ssvc_breakdown', label: 'SSVC Priority', section: 'secondary' },
  { id: 'posture_chart', label: 'Posture Timeline', section: 'bottom' },
  { id: 'top_assets', label: 'Top Risky Assets', section: 'bottom' },
  { id: 'recent_scans', label: 'Recent Scans', section: 'bottom' },
  { id: 'recent_findings', label: 'Recent Findings', section: 'bottom' },
]

const STORAGE_KEY = 'horus_dashboard_widgets'

function loadWidgetConfig(): Record<WidgetId, boolean> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) return JSON.parse(raw) as Record<WidgetId, boolean>
  } catch {}
  return Object.fromEntries(ALL_WIDGETS.map((w) => [w.id, true])) as Record<WidgetId, boolean>
}

function saveWidgetConfig(config: Record<WidgetId, boolean>) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(config))
}

const STATUS_COLOR: Record<string, string> = {
  completed: 'text-mode-auto',
  running: 'text-accent',
  failed: 'text-severity-critical',
  pending: 'text-muted',
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null)
  const [findings, setFindings] = useState<unknown[]>([])
  const [orgId, setOrgId] = useState<string | undefined>()
  const [widgetConfig, setWidgetConfig] = useState<Record<WidgetId, boolean>>(loadWidgetConfig)
  const [customizeOpen, setCustomizeOpen] = useState(false)
  const navigate = useNavigate()

  const refresh = useCallback(() => {
    api.get<DashboardStats>('/dashboard/stats').then(setStats).catch(() => {})
    api.get<DashboardMetrics>('/dashboard/metrics').then(setMetrics).catch(() => {})
  }, [])

  useEffect(() => {
    refresh()
    api
      .get<{ items: unknown[] }>('/findings?per_page=8')
      .then((r) => setFindings(r.items))
      .catch(() => {})
    supabase.auth.getSession().then(async ({ data }) => {
      if (!data.session) return
      const { data: profile } = await supabase
        .from('profiles')
        .select('org_id')
        .eq('id', data.session.user.id)
        .single()
      setOrgId(profile?.org_id)
    })
  }, [refresh])

  useRealtime('agent_runs', orgId, refresh)
  useRealtime('findings', orgId, () => {
    refresh()
    api
      .get<{ items: unknown[] }>('/findings?per_page=8')
      .then((r) => setFindings(r.items))
      .catch(() => {})
  })

  const show = (id: WidgetId) => widgetConfig[id] !== false

  function toggleWidget(id: WidgetId) {
    const next = { ...widgetConfig, [id]: !widgetConfig[id] }
    setWidgetConfig(next)
    saveWidgetConfig(next)
  }

  const primaryVisible = show('act_now') || show('kev_exposure') || show('asset_coverage') || show('mttr')
  const secondaryVisible = show('findings_trend') || show('open_severity') || show('ssvc_breakdown')
  const bottomVisible = show('top_assets') || show('recent_scans')

  return (
    <div className="space-y-6">
      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-horus-ivory tracking-wide">Dashboard</h1>
          <p className="text-xs text-muted mt-0.5">Security operations overview</p>
        </div>
        <button
          onClick={() => setCustomizeOpen((o) => !o)}
          className={cn(
            'flex items-center gap-1.5 px-3 py-1.5 rounded-md border text-xs transition-colors',
            customizeOpen
              ? 'bg-horus-lapis/20 border-horus-lapis/40 text-horus-ivory'
              : 'border-white/10 text-muted hover:text-horus-ivory hover:border-white/30',
          )}
        >
          <Settings2 className="w-3.5 h-3.5" />
          Customize
        </button>
      </div>

      {/* ── Customize panel ─────────────────────────────────────────────────── */}
      {customizeOpen && (
        <div className="glass rounded-lg p-4 border border-horus-lapis/20">
          <div className="flex items-center justify-between mb-3">
            <p className="text-xs font-medium text-horus-ivory uppercase tracking-wider">
              Widget Visibility
            </p>
            <button
              onClick={() => setCustomizeOpen(false)}
              className="text-muted hover:text-white transition-colors"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="grid grid-cols-3 sm:grid-cols-4 gap-y-2 gap-x-4">
            {ALL_WIDGETS.map((w) => (
              <label
                key={w.id}
                className="flex items-center gap-2 cursor-pointer group select-none"
                onClick={() => toggleWidget(w.id)}
              >
                <div
                  className={cn(
                    'w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors',
                    widgetConfig[w.id]
                      ? 'bg-horus-lapis border-horus-lapis'
                      : 'border-white/20 bg-transparent',
                  )}
                >
                  {widgetConfig[w.id] && <CheckCircle2 className="w-3 h-3 text-white" />}
                </div>
                <span className="text-xs text-muted group-hover:text-horus-ivory transition-colors">
                  {w.label}
                </span>
              </label>
            ))}
          </div>
        </div>
      )}

      {/* ── Primary KPIs ────────────────────────────────────────────────────── */}
      {primaryVisible && (
        <div className="stagger grid grid-cols-2 lg:grid-cols-4 gap-4">
          {show('act_now') && <ActNowCard value={metrics?.ssvc.act ?? null} />}
          {show('kev_exposure') && <KevCard value={metrics?.kev_active ?? null} />}
          {show('asset_coverage') && <CoverageCard coverage={metrics?.asset_coverage ?? null} />}
          {show('mttr') && <MttrCard days={metrics?.mttr_critical_days ?? null} />}
        </div>
      )}

      {/* ── Secondary row ───────────────────────────────────────────────────── */}
      {secondaryVisible && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {show('findings_trend') && (
            <FindingsTrendCard trend={metrics?.findings_trend ?? null} />
          )}
          {show('open_severity') && (
            <SeverityBreakdownCard sev={metrics?.open_by_severity ?? null} />
          )}
          {show('ssvc_breakdown') && (
            <SSVCBreakdownCard ssvc={metrics?.ssvc ?? null} />
          )}
        </div>
      )}

      {/* ── Posture timeline ─────────────────────────────────────────────────── */}
      {show('posture_chart') && <PostureTimeline />}

      {/* ── Bottom: risky assets + recent scans ─────────────────────────────── */}
      {bottomVisible && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {show('top_assets') && (
            <TopRiskyAssetsCard
              assets={metrics?.top_risky_assets ?? []}
              navigate={navigate}
            />
          )}
          {show('recent_scans') && (
            <RecentScansCard scans={stats?.recent_scans ?? []} navigate={navigate} />
          )}
        </div>
      )}

      {/* ── Recent findings ─────────────────────────────────────────────────── */}
      {show('recent_findings') && findings.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-xs font-medium text-muted uppercase tracking-wider">
            Recent Findings
          </h2>
          <div className="space-y-2">
            {(findings as Parameters<typeof FindingCard>[0]['finding'][])
              .slice(0, 6)
              .map((f) => (
                <FindingCard
                  key={(f as { id: string }).id}
                  finding={f as Parameters<typeof FindingCard>[0]['finding']}
                />
              ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Primary KPI cards ─────────────────────────────────────────────────────────

function ActNowCard({ value }: { value: number | null }) {
  const isUrgent = value !== null && value > 0
  return (
    <div
      className={cn(
        'glass rounded-lg p-4 border transition-colors',
        isUrgent ? 'border-severity-critical/30' : 'border-white/5',
      )}
    >
      <div className="flex items-center justify-between mb-3">
        <div
          className={cn(
            'w-8 h-8 rounded-md flex items-center justify-center',
            isUrgent ? 'bg-severity-critical/10' : 'bg-mode-auto/10',
          )}
        >
          <Target
            className={cn('w-4 h-4', isUrgent ? 'text-severity-critical' : 'text-mode-auto')}
          />
        </div>
        {isUrgent && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-severity-critical/10 text-severity-critical text-[10px] font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-severity-critical animate-pulse" />
            URGENT
          </span>
        )}
      </div>
      <div
        className={cn(
          'text-3xl font-bold leading-none mb-1',
          isUrgent ? 'text-severity-critical' : 'text-mode-auto',
        )}
      >
        {value ?? '—'}
      </div>
      <div className="text-xs text-muted uppercase tracking-wider">Act Now</div>
      <div className="text-[10px] text-white/30 mt-1">require immediate action</div>
    </div>
  )
}

function KevCard({ value }: { value: number | null }) {
  const hasKev = value !== null && value > 0
  return (
    <div
      className={cn(
        'glass rounded-lg p-4 border transition-colors',
        hasKev ? 'border-severity-critical/20' : 'border-white/5',
      )}
    >
      <div className="mb-3">
        <div
          className={cn(
            'w-8 h-8 rounded-md flex items-center justify-center',
            hasKev ? 'bg-severity-critical/10' : 'bg-mode-auto/10',
          )}
        >
          <AlertTriangle
            className={cn('w-4 h-4', hasKev ? 'text-severity-critical' : 'text-mode-auto')}
          />
        </div>
      </div>
      <div
        className={cn(
          'text-3xl font-bold leading-none mb-1',
          hasKev ? 'text-severity-critical' : 'text-mode-auto',
        )}
      >
        {value ?? '—'}
      </div>
      <div className="text-xs text-muted uppercase tracking-wider">KEV Exposure</div>
      <div className="text-[10px] text-white/30 mt-1">actively exploited in the wild</div>
    </div>
  )
}

function CoverageCard({
  coverage,
}: {
  coverage: { scanned: number; total: number; pct: number } | null
}) {
  const pct = coverage?.pct ?? null
  const colorClass =
    pct === null
      ? 'text-muted'
      : pct >= 80
        ? 'text-mode-auto'
        : pct >= 50
          ? 'text-severity-medium'
          : 'text-severity-critical'
  const borderClass =
    pct === null
      ? 'border-white/5'
      : pct >= 80
        ? 'border-mode-auto/10'
        : pct >= 50
          ? 'border-severity-medium/20'
          : 'border-severity-critical/20'
  return (
    <div className={cn('glass rounded-lg p-4 border transition-colors', borderClass)}>
      <div className="flex items-center justify-between mb-3">
        <div className="w-8 h-8 rounded-md flex items-center justify-center bg-horus-lapis/10">
          <Shield className="w-4 h-4 text-horus-lapis" />
        </div>
        {coverage && (
          <span className="text-[10px] text-white/30">
            {coverage.scanned}/{coverage.total}
          </span>
        )}
      </div>
      <div className={cn('text-3xl font-bold leading-none mb-1', colorClass)}>
        {pct !== null ? `${pct}%` : '—'}
      </div>
      <div className="text-xs text-muted uppercase tracking-wider">Asset Coverage</div>
      <div className="text-[10px] text-white/30 mt-1">assets scanned in 7 days</div>
    </div>
  )
}

function MttrCard({ days }: { days: number | null }) {
  const colorClass =
    days === null
      ? 'text-muted'
      : days <= 7
        ? 'text-mode-auto'
        : days <= 14
          ? 'text-severity-medium'
          : 'text-severity-critical'
  return (
    <div className="glass rounded-lg p-4 border border-white/5">
      <div className="mb-3">
        <div className="w-8 h-8 rounded-md flex items-center justify-center bg-white/5">
          <Clock className="w-4 h-4 text-muted" />
        </div>
      </div>
      <div className={cn('text-3xl font-bold leading-none mb-1', colorClass)}>
        {days != null ? `${days}d` : '—'}
      </div>
      <div className="text-xs text-muted uppercase tracking-wider">MTTR Critical</div>
      <div className="text-[10px] text-white/30 mt-1">mean time to remediate</div>
    </div>
  )
}

// ── Secondary cards ───────────────────────────────────────────────────────────

function FindingsTrendCard({
  trend,
}: {
  trend: { new_this_week: number; new_prev_week: number; resolved_this_week: number } | null
}) {
  const delta = trend ? trend.new_this_week - trend.new_prev_week : 0
  const improved = delta < 0
  const flat = delta === 0
  const TrendIcon = flat ? Minus : improved ? TrendingDown : TrendingUp
  const trendColor = flat ? 'text-muted' : improved ? 'text-mode-auto' : 'text-severity-critical'

  return (
    <div className="glass rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <p className="text-xs text-muted uppercase tracking-wider font-medium">Findings Trend</p>
        {trend && (
          <div className={cn('flex items-center gap-1 text-xs font-medium', trendColor)}>
            <TrendIcon className="w-3.5 h-3.5" />
            <span>
              {flat
                ? 'no change'
                : `${Math.abs(delta)} ${improved ? 'fewer' : 'more'}`}
            </span>
          </div>
        )}
      </div>
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs text-white/50">New this week</span>
          <span className="text-sm font-semibold text-horus-ivory">
            {trend?.new_this_week ?? '—'}
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-xs text-white/50">Previous week</span>
          <span className="text-sm text-muted">{trend?.new_prev_week ?? '—'}</span>
        </div>
        <div className="border-t border-white/5 pt-3 flex items-center justify-between">
          <span className="text-xs text-white/50">Resolved this week</span>
          <span className="text-sm font-semibold text-mode-auto">
            {trend?.resolved_this_week ?? '—'}
          </span>
        </div>
      </div>
    </div>
  )
}

function SeverityBreakdownCard({
  sev,
}: {
  sev: { critical: number; high: number; medium: number; low: number } | null
}) {
  const total = sev ? sev.critical + sev.high + sev.medium + sev.low : 0
  const bars = [
    { label: 'Critical', value: sev?.critical ?? 0, color: 'bg-severity-critical' },
    { label: 'High', value: sev?.high ?? 0, color: 'bg-severity-high' },
    { label: 'Medium', value: sev?.medium ?? 0, color: 'bg-severity-medium' },
    { label: 'Low', value: sev?.low ?? 0, color: 'bg-accent' },
  ]
  return (
    <div className="glass rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <p className="text-xs text-muted uppercase tracking-wider font-medium">Open by Severity</p>
        <span className="text-xs text-white/40">{total} total</span>
      </div>
      <div className="space-y-2.5">
        {bars.map((b) => (
          <div key={b.label} className="flex items-center gap-3">
            <span className="text-xs text-white/50 w-12 shrink-0">{b.label}</span>
            <div className="flex-1 h-1.5 bg-white/5 rounded-full overflow-hidden">
              <div
                className={cn('h-full rounded-full transition-all duration-500', b.color)}
                style={{ width: total > 0 ? `${Math.max(4, (b.value / total) * 100)}%` : '0%' }}
              />
            </div>
            <span className="text-xs font-medium text-horus-ivory w-5 text-right">{b.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function SSVCBreakdownCard({
  ssvc,
}: {
  ssvc: {
    act: number
    attend: number
    track_star: number
    track: number
    none: number
  } | null
}) {
  const total = ssvc ? ssvc.act + ssvc.attend + ssvc.track_star + ssvc.track : 0
  const bands = [
    {
      label: 'Act',
      value: ssvc?.act ?? 0,
      bar: 'bg-severity-critical',
      text: 'text-severity-critical',
    },
    {
      label: 'Attend',
      value: ssvc?.attend ?? 0,
      bar: 'bg-severity-high',
      text: 'text-severity-high',
    },
    {
      label: 'Track*',
      value: ssvc?.track_star ?? 0,
      bar: 'bg-severity-medium',
      text: 'text-severity-medium',
    },
    { label: 'Track', value: ssvc?.track ?? 0, bar: 'bg-white/20', text: 'text-muted' },
  ]
  return (
    <div className="glass rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <p className="text-xs text-muted uppercase tracking-wider font-medium">SSVC Priority</p>
        <span className="text-xs text-white/40">{total} findings</span>
      </div>
      {/* Stacked bar */}
      <div className="flex h-2 rounded-full overflow-hidden mb-4 gap-px bg-white/5">
        {total > 0 ? (
          bands.map((b) =>
            b.value > 0 ? (
              <div
                key={b.label}
                className={cn('h-full transition-all duration-500', b.bar)}
                style={{ width: `${(b.value / total) * 100}%` }}
              />
            ) : null,
          )
        ) : null}
      </div>
      <div className="grid grid-cols-2 gap-2">
        {bands.map((b) => (
          <div key={b.label} className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <div className={cn('w-2 h-2 rounded-full shrink-0', b.bar)} />
              <span className="text-xs text-white/50">{b.label}</span>
            </div>
            <span className={cn('text-xs font-semibold', b.text)}>{b.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Bottom cards ──────────────────────────────────────────────────────────────

function TopRiskyAssetsCard({
  assets,
  navigate,
}: {
  assets: { id: string; name: string; critical: number; high: number; act: number }[]
  navigate: ReturnType<typeof useNavigate>
}) {
  return (
    <div className="glass rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <p className="text-xs text-muted uppercase tracking-wider font-medium">Top Risky Assets</p>
        <Server className="w-3.5 h-3.5 text-muted" />
      </div>
      {assets.length === 0 ? (
        <p className="text-xs text-muted text-center py-6">No risky assets — looking good</p>
      ) : (
        <div className="space-y-2">
          {assets.map((a) => (
            <button
              key={a.id}
              onClick={() => navigate(`/assets/${a.id}`)}
              className="w-full flex items-center justify-between glass glass-hover rounded-md p-2.5 text-left"
            >
              <div className="min-w-0">
                <p className="text-xs font-medium text-horus-ivory truncate">{a.name}</p>
                {a.act > 0 && (
                  <p className="text-[10px] text-severity-critical mt-0.5">{a.act} act now</p>
                )}
              </div>
              <div className="flex items-center gap-1.5 shrink-0 ml-2">
                {a.critical > 0 && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-severity-critical/10 text-severity-critical font-medium">
                    {a.critical}C
                  </span>
                )}
                {a.high > 0 && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-severity-high/10 text-severity-high font-medium">
                    {a.high}H
                  </span>
                )}
                <ChevronRight className="w-3 h-3 text-muted" />
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

function RecentScansCard({
  scans,
  navigate,
}: {
  scans: { id: string; status: string; created_at: string; assets: { name: string } }[]
  navigate: ReturnType<typeof useNavigate>
}) {
  return (
    <div className="glass rounded-lg p-4">
      <div className="flex items-center justify-between mb-4">
        <p className="text-xs text-muted uppercase tracking-wider font-medium">Recent Scans</p>
        <Eye className="w-3.5 h-3.5 text-muted" />
      </div>
      {scans.length === 0 ? (
        <p className="text-xs text-muted text-center py-6">No scans yet</p>
      ) : (
        <div className="space-y-2">
          {scans.map((scan) => (
            <button
              key={scan.id}
              onClick={() => navigate(`/scans/${scan.id}`)}
              className="w-full glass glass-hover rounded-md p-2.5 text-left"
            >
              <p className="text-xs font-medium text-horus-ivory truncate">
                {scan.assets?.name ?? 'Unknown'}
              </p>
              <div className="flex items-center justify-between mt-1">
                <span
                  className={cn(
                    'text-[10px] capitalize',
                    STATUS_COLOR[scan.status] ?? 'text-muted',
                  )}
                >
                  {scan.status}
                </span>
                <span className="text-[10px] text-white/30">
                  {formatDistanceToNow(new Date(scan.created_at))} ago
                </span>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
