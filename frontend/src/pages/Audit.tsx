import { useEffect, useState } from 'react'
import { ScrollText, ChevronLeft, ChevronRight } from 'lucide-react'
import { api } from '../lib/api'
import { useRole } from '../hooks/useRole'
import { cn } from '../lib/utils'

interface AuditEntry {
  id: string
  actor_type: 'user' | 'agent' | 'system'
  actor_id: string
  actor_name: string | null
  action: string
  entity_type: string | null
  entity_id: string | null
  metadata: Record<string, unknown>
  created_at: string
}

interface AuditResponse {
  entries: AuditEntry[]
  total: number
  page: number
  per_page: number
}

// Maps known action strings to a readable label and a tone color.
const ACTION_META: Record<string, { label: string; tone: string }> = {
  'team.member_invited': { label: 'Member invited', tone: 'text-accent' },
  'team.role_changed': { label: 'Role changed', tone: 'text-mode-approval' },
  'team.member_removed': { label: 'Member removed', tone: 'text-severity-critical' },
  'asset.deleted': { label: 'Asset deleted', tone: 'text-severity-critical' },
  'scan.triggered': { label: 'Scan triggered', tone: 'text-accent' },
  'permission_policy.created': { label: 'Policy created', tone: 'text-mode-auto' },
  'permission_policy.updated': { label: 'Policy updated', tone: 'text-mode-approval' },
  'permission_policy.deleted': { label: 'Policy deleted', tone: 'text-severity-critical' },
  'suggestion.approved': { label: 'Suggestion approved', tone: 'text-mode-auto' },
  'suggestion.rejected': { label: 'Suggestion rejected', tone: 'text-severity-high' },
}

const ACTION_FILTERS = ['', ...Object.keys(ACTION_META)]

function actionMeta(action: string) {
  return ACTION_META[action] ?? { label: action, tone: 'text-muted' }
}

const PER_PAGE = 50

export default function Audit() {
  const { can } = useRole()
  const [data, setData] = useState<AuditResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [action, setAction] = useState('')
  const [page, setPage] = useState(1)

  const load = () => {
    setLoading(true)
    const params = new URLSearchParams({ page: String(page), per_page: String(PER_PAGE) })
    if (action) params.set('action', action)
    api
      .get<AuditResponse>(`/audit?${params}`)
      .then((d) => setData(d))
      .finally(() => setLoading(false))
  }

  useEffect(load, [action, page])
  useEffect(() => { setPage(1) }, [action])

  if (!can('admin')) {
    return (
      <div className="text-sm text-muted">
        Audit trail is restricted to administrators.
      </div>
    )
  }

  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))
  const select = 'bg-bg border border-border text-sm text-white rounded px-3 py-1.5 focus:outline-none focus:border-accent'

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ScrollText className="w-5 h-5 text-accent" />
          <h1 className="text-lg font-semibold">Audit log</h1>
        </div>
        <select className={select} value={action} onChange={(e) => setAction(e.target.value)}>
          {ACTION_FILTERS.map((a) => (
            <option key={a} value={a}>{a ? actionMeta(a).label : 'All actions'}</option>
          ))}
        </select>
      </div>

      <div className="bg-surface border border-border rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-xs text-muted">
              <th className="text-left py-3 px-4 font-medium">When</th>
              <th className="text-left py-3 px-4 font-medium">Actor</th>
              <th className="text-left py-3 px-4 font-medium">Action</th>
              <th className="text-left py-3 px-4 font-medium">Target</th>
              <th className="text-left py-3 px-4 font-medium">Details</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} className="py-8 text-center text-muted text-xs">Loading…</td></tr>
            ) : !data?.entries.length ? (
              <tr><td colSpan={5} className="py-8 text-center text-muted text-xs">No audit entries yet.</td></tr>
            ) : (
              data.entries.map((e) => {
                const meta = actionMeta(e.action)
                return (
                  <tr key={e.id} className="border-b border-border hover:bg-white/[0.02] transition-colors align-top">
                    <td className="py-3 px-4 text-xs text-muted whitespace-nowrap">
                      {new Date(e.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4">
                      <p className="text-white">{e.actor_name || e.actor_id}</p>
                      <p className="text-xs text-muted capitalize">{e.actor_type}</p>
                    </td>
                    <td className={cn('py-3 px-4 font-medium whitespace-nowrap', meta.tone)}>
                      {meta.label}
                    </td>
                    <td className="py-3 px-4 text-xs text-muted">
                      {e.entity_type ? (
                        <span>
                          {e.entity_type}
                          {e.entity_id && <span className="block font-mono text-[10px] opacity-70">{e.entity_id}</span>}
                        </span>
                      ) : '—'}
                    </td>
                    <td className="py-3 px-4 text-xs text-muted">
                      {e.metadata && Object.keys(e.metadata).length > 0 ? (
                        <code className="font-mono text-[11px] text-white/70 break-all">
                          {JSON.stringify(e.metadata)}
                        </code>
                      ) : '—'}
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-xs text-muted">
        <span>{total} {total === 1 ? 'entry' : 'entries'}</span>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            className="flex items-center gap-1 hover:text-white disabled:opacity-30 transition-colors"
          >
            <ChevronLeft className="w-4 h-4" /> Prev
          </button>
          <span>Page {page} / {totalPages}</span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="flex items-center gap-1 hover:text-white disabled:opacity-30 transition-colors"
          >
            Next <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  )
}
