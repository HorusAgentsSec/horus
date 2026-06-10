import { useEffect, useState } from 'react'
import { AlertTriangle, Server, Lightbulb, Clock } from 'lucide-react'
import { api } from '../lib/api'
import { FindingCard } from '../components/findings/FindingCard'
import { PostureTimeline } from '../components/PostureTimeline'
import { useRealtime } from '../hooks/useRealtime'
import { supabase } from '../lib/supabase'
import { formatDistanceToNow } from 'date-fns'

interface Stats {
  total_assets: number
  open_findings_by_severity: Record<string, number>
  recent_scans: { id: string; status: string; created_at: string; assets: { name: string } }[]
  pending_suggestions: number
}

const STATUS_COLOR: Record<string, string> = {
  completed: 'text-mode-auto',
  running: 'text-accent',
  failed: 'text-severity-critical',
  pending: 'text-muted',
}

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null)
  const [findings, setFindings] = useState<unknown[]>([])
  const [orgId, setOrgId] = useState<string | undefined>()

  useEffect(() => {
    api.get<Stats>('/dashboard/stats').then(setStats)
    api.get<{ items: unknown[] }>('/findings?per_page=10').then((r) => setFindings(r.items))
    supabase.auth.getSession().then(async ({ data }) => {
      if (!data.session) return
      const { data: profile } = await supabase
        .from('profiles')
        .select('org_id')
        .eq('id', data.session.user.id)
        .single()
      setOrgId(profile?.org_id)
    })
  }, [])

  useRealtime('agent_runs', orgId, () => {
    api.get<Stats>('/dashboard/stats').then(setStats)
  })

  useRealtime('findings', orgId, () => {
    api.get<{ items: unknown[] }>('/findings?per_page=10').then((r) => setFindings(r.items))
  })

  if (!stats) return <div className="text-white/60 text-sm">Loading…</div>

  const critical = stats.open_findings_by_severity['critical'] ?? 0

  return (
    <div className="space-y-8">
      <h1 className="text-lg font-semibold">Dashboard</h1>

      <div className="grid grid-cols-4 gap-4">
        <StatCard icon={<Server />} label="Assets" value={stats.total_assets} />
        <StatCard icon={<AlertTriangle />} label="Critical" value={critical} accent="text-severity-critical" />
        <StatCard icon={<Lightbulb />} label="Pending Suggestions" value={stats.pending_suggestions} />
        <StatCard
          icon={<Clock />}
          label="Last Scan"
          value={
            stats.recent_scans[0]
              ? formatDistanceToNow(new Date(stats.recent_scans[0].created_at)) + ' ago'
              : 'Never'
          }
        />
      </div>

      <PostureTimeline />

      <div className="grid grid-cols-3 gap-6">
        <div className="col-span-2 space-y-3">
          <h2 className="text-sm font-medium text-white/60 uppercase">Recent Findings</h2>
          {(findings as Parameters<typeof FindingCard>[0]['finding'][]).map((f) => (
            <FindingCard key={(f as {id:string}).id} finding={f as Parameters<typeof FindingCard>[0]['finding']} />
          ))}
        </div>
        <div className="space-y-3">
          <h2 className="text-sm font-medium text-white/60 uppercase">Recent Scans</h2>
          {stats.recent_scans.map((scan) => (
            <div key={scan.id} className="glass glass-hover rounded-lg p-3">
              <p className="text-sm text-horus-ivory">{scan.assets?.name}</p>
              <div className="flex items-center justify-between mt-1">
                <span className={`text-xs capitalize ${STATUS_COLOR[scan.status] ?? 'text-white/40'}`}>
                  {scan.status}
                </span>
                <span className="text-xs text-white/40">
                  {formatDistanceToNow(new Date(scan.created_at))} ago
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function StatCard({
  icon,
  label,
  value,
  accent = 'text-white',
}: {
  icon: React.ReactNode
  label: string
  value: string | number
  accent?: string
}) {
  return (
    <div className="glass glass-hover rounded-lg p-4">
      <div className="flex items-center gap-2 text-white/60 mb-2">
        <span className="w-4 h-4 text-horus-lapis">{icon}</span>
        <span className="text-xs uppercase">{label}</span>
      </div>
      <p className={`text-2xl font-semibold ${accent}`}>{value}</p>
    </div>
  )
}
