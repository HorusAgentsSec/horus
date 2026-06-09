import { useEffect, useState } from 'react'
import { ShieldAlert, RefreshCw, AlertTriangle, BadgeCheck, Users } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { cn } from '../lib/utils'
import { useRole } from '../hooks/useRole'

// ── Types ────────────────────────────────────────────────────────────────────

interface BreachStats {
  total_breaches: number
  employees_affected: number
  sensitive_breaches: number
  avg_karma_score: number
}

interface EmployeeInfo {
  full_name: string | null
  email: string
  department: string | null
  karma_score: number
}

interface Breach {
  id: string
  employee_id: string
  breach_name: string
  breach_date: string | null
  data_classes: string[]
  is_sensitive: boolean
  discovered_at: string
  employees: EmployeeInfo | null
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function karmaColor(score: number) {
  if (score >= 80) return 'text-green-400'
  if (score >= 50) return 'text-yellow-400'
  return 'text-red-400'
}

function karmaCardColor(score: number) {
  if (score >= 80) return 'text-green-400'
  if (score >= 50) return 'text-yellow-400'
  return 'text-red-400'
}

function formatDate(dateStr: string | null) {
  if (!dateStr) return '—'
  try {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  } catch {
    return dateStr
  }
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  valueClass,
  icon: Icon,
}: {
  label: string
  value: number | string
  valueClass?: string
  icon: React.ElementType
}) {
  return (
    <div className="bg-surface border border-border rounded-lg px-5 py-4 flex items-center gap-4">
      <div className="rounded-md bg-white/5 p-2">
        <Icon className="w-5 h-5 text-accent" />
      </div>
      <div>
        <p className="text-xs text-muted mb-0.5">{label}</p>
        <p className={cn('text-2xl font-semibold', valueClass)}>{value}</p>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function CredentialExposure() {
  const { can } = useRole()
  const [stats, setStats] = useState<BreachStats | null>(null)
  const [breaches, setBreaches] = useState<Breach[]>([])
  const [loading, setLoading] = useState(true)
  const [checking, setChecking] = useState(false)
  const [status, setStatus] = useState<{ msg: string; ok: boolean } | null>(null)

  const load = () => {
    setLoading(true)
    Promise.all([
      api.get<BreachStats>('/hibp/stats'),
      api.get<Breach[]>('/hibp/breaches'),
    ])
      .then(([s, b]) => {
        setStats(s)
        setBreaches(b)
      })
      .catch((err) => {
        setStatus({ msg: friendlyErrorMessage(err), ok: false })
      })
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  const runCheck = async () => {
    setChecking(true)
    setStatus(null)
    try {
      await api.post('/hibp/check', {})
      setStatus({ msg: 'Queued — check will run in background', ok: true })
    } catch (err) {
      setStatus({ msg: friendlyErrorMessage(err), ok: false })
    } finally {
      setChecking(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-accent" />
          <h1 className="text-lg font-semibold">Credential Exposure</h1>
        </div>
        {can('admin') && (
          <button
            onClick={runCheck}
            disabled={checking}
            className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-1.5 rounded-md hover:bg-accent/20 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={cn('w-4 h-4', checking && 'animate-spin')} />
            Run HIBP Check
          </button>
        )}
      </div>

      <p className="text-sm text-muted -mt-2">
        Cross-references your organisation's email domain against HaveIBeenPwned to surface employees
        whose credentials have appeared in known data breaches. Sensitive breaches (passwords /
        auth tokens) trigger an automatic karma-score penalty.
      </p>

      {/* Status message */}
      {status && (
        <div
          className={cn(
            'text-sm rounded-md px-3 py-2 border',
            status.ok
              ? 'bg-severity-low/10 border-severity-low/30 text-severity-low'
              : 'bg-severity-critical/10 border-severity-critical/30 text-severity-critical',
          )}
        >
          {status.msg}
        </div>
      )}

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <StatCard
            label="Breaches found"
            value={stats.total_breaches}
            icon={AlertTriangle}
          />
          <StatCard
            label="Employees affected"
            value={stats.employees_affected}
            icon={Users}
          />
          <StatCard
            label="Avg. karma score"
            value={stats.avg_karma_score}
            valueClass={karmaCardColor(stats.avg_karma_score)}
            icon={BadgeCheck}
          />
        </div>
      )}

      {/* Breaches table */}
      <div className="bg-surface border border-border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-muted" />
          <span className="text-sm font-medium">Breach records</span>
          {!loading && (
            <span className="text-xs text-muted ml-auto">{breaches.length} record{breaches.length !== 1 ? 's' : ''}</span>
          )}
        </div>

        {loading ? (
          <div className="text-xs text-muted py-10 text-center">Loading…</div>
        ) : !breaches.length ? (
          <div className="flex flex-col items-center gap-2 text-center py-12 text-muted">
            <BadgeCheck className="w-8 h-8 opacity-40 text-green-400" />
            <p className="text-sm">No credential breaches found.</p>
            <p className="text-xs max-w-md">
              Run an HIBP check to scan your domain against known data breaches, or ensure a domain
              is configured in your organisation settings.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-muted">
                  <th className="text-left px-4 py-2 font-medium">Employee</th>
                  <th className="text-left px-4 py-2 font-medium">Department</th>
                  <th className="text-left px-4 py-2 font-medium">Breach</th>
                  <th className="text-left px-4 py-2 font-medium">Date</th>
                  <th className="text-left px-4 py-2 font-medium">Sensitive</th>
                  <th className="text-left px-4 py-2 font-medium">Karma</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {breaches.map((b) => {
                  const emp = b.employees
                  return (
                    <tr key={b.id} className="hover:bg-white/[0.02] transition-colors">
                      {/* Employee */}
                      <td className="px-4 py-3">
                        <div className="font-medium text-white truncate max-w-[180px]">
                          {emp?.full_name ?? '—'}
                        </div>
                        <div className="text-xs text-muted truncate max-w-[180px]">
                          {emp?.email ?? '—'}
                        </div>
                      </td>

                      {/* Department */}
                      <td className="px-4 py-3 text-muted">
                        {emp?.department ?? <span className="opacity-40">—</span>}
                      </td>

                      {/* Breach name */}
                      <td className="px-4 py-3">
                        <span className="font-medium text-white">{b.breach_name}</span>
                        {b.data_classes.length > 0 && (
                          <div className="text-xs text-muted mt-0.5 truncate max-w-[200px]">
                            {b.data_classes.slice(0, 3).join(', ')}
                            {b.data_classes.length > 3 && ` +${b.data_classes.length - 3}`}
                          </div>
                        )}
                      </td>

                      {/* Date */}
                      <td className="px-4 py-3 text-muted whitespace-nowrap">
                        {formatDate(b.breach_date)}
                      </td>

                      {/* Sensitive badge */}
                      <td className="px-4 py-3">
                        {b.is_sensitive ? (
                          <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-red-900/40 text-red-300 border border-red-800/40">
                            Sensitive
                          </span>
                        ) : (
                          <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-white/5 text-white/40">
                            Low risk
                          </span>
                        )}
                      </td>

                      {/* Karma score */}
                      <td className="px-4 py-3">
                        {emp ? (
                          <span className={cn('font-semibold tabular-nums', karmaColor(emp.karma_score))}>
                            {emp.karma_score}
                          </span>
                        ) : (
                          <span className="text-muted opacity-40">—</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
