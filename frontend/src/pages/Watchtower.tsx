import { useEffect, useState, useRef } from 'react'
import { createPortal } from 'react-dom'
import { Link } from 'react-router-dom'
import { Eye, RefreshCw, ShieldAlert, X } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { cn, severityBg, severityColor } from '../lib/utils'
import { useRole } from '../hooks/useRole'

interface Alert {
  id: string
  cve_id: string
  product: string
  version: string
  severity: string | null
  reason: string
  finding_id: string | null
  created_at: string
  assets: { name: string } | null
}

function timeAgo(iso: string): string {
  const d = new Date(iso)
  const diff = (Date.now() - d.getTime()) / 1000
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return d.toLocaleDateString()
}

export default function Watchtower() {
  const { can } = useRole()
  const [items, setItems] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [status, setStatus] = useState<{ msg: string; ok: boolean } | null>(null)
  
  // Progress modal state
  const [running, setRunning] = useState(false)
  const [progressLogs, setProgressLogs] = useState<string[]>([])
  const logsEndRef = useRef<HTMLDivElement>(null)

  const load = () => {
    setLoading(true)
    api.get<Alert[]>('/watchtower/alerts').then(setItems).finally(() => setLoading(false))
  }
  useEffect(load, [])

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [progressLogs])

  const runNow = async () => {
    setRunning(true)
    setProgressLogs(['Starting Watchtower check...'])
    
    // We get the token to use in the SSE connection since EventSource doesn't support custom headers easily.
    const { data } = await import('../lib/supabase').then(m => m.supabase.auth.getSession())
    const token = data.session?.access_token
    const url = import.meta.env.VITE_API_URL || '/api'
    const eventSource = new EventSource(`${url}/watchtower/stream?token=${token}`)

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.msg) {
          setProgressLogs((prev) => [...prev, data.msg])
        } else if (data.done) {
          setProgressLogs((prev) => [...prev, `Check finished! Found ${data.result.alerts} new alerts. Closing...`])
          eventSource.close()
          load() // Reload alerts
          setTimeout(() => setRunning(false), 1500)
        }
      } catch (e) {
        console.error('Error parsing SSE', e)
      }
    }

    eventSource.onerror = (err) => {
      console.error('EventSource failed', err)
      setProgressLogs((prev) => [...prev, 'Error: Connection lost or stream failed.'])
      eventSource.close()
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Eye className="w-5 h-5 text-accent" />
          <h1 className="text-lg font-semibold">Watchtower</h1>
        </div>
        {can('admin') && (
          <button
            onClick={runNow}
            disabled={running}
            className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-1.5 rounded-md hover:bg-accent/20 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={cn('w-4 h-4', running && 'animate-spin')} />
            Check now
          </button>
        )}
      </div>

      <p className="text-sm text-muted -mt-2">
        Continuous exposure monitoring. A scan is a point-in-time snapshot, but new threats emerge
        every day. Watchtower keeps an inventory of the software found on your assets and, each day,
        re-checks it against CVEs that just became actively exploited (CISA KEV) — without
        re-scanning. When something you already run starts being exploited in the wild, you get
        alerted the same day.
      </p>

      {status && !running && (
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

      {running && createPortal(
        <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 sm:p-6 md:p-8">
          <div className="w-full max-w-2xl bg-surface border border-white/10 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="flex items-center justify-between px-4 py-3 border-b border-white/10 bg-white/[0.02]">
              <h2 className="text-sm font-medium flex items-center gap-2 text-white">
                <RefreshCw className="w-4 h-4 animate-spin text-accent" />
                Watchtower Progress
              </h2>
              <button onClick={() => setRunning(false)} className="text-white/60 hover:text-white transition-colors">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-4 sm:p-6 bg-[#0a0a0a] font-mono text-xs overflow-y-auto flex-1 min-h-[16rem] break-all">
              {progressLogs.map((log, idx) => (
                <div key={idx} className="mb-1 text-white/80">
                  <span className="text-accent/60 mr-2">{'>'}</span>{log}
                </div>
              ))}
              <div ref={logsEndRef} />
            </div>
          </div>
        </div>,
        document.body
      )}

      <div className="space-y-2">
        {loading ? (
          <div className="text-xs text-muted py-8 text-center">Loading…</div>
        ) : !items.length ? (
          <div className="flex flex-col items-center gap-2 text-center py-12 text-muted">
            <ShieldAlert className="w-8 h-8 opacity-40" />
            <p className="text-sm">No active-exploitation alerts yet.</p>
            <p className="text-xs max-w-md">
              Watchtower watches your inventory in the background. The more scans you run, the more
              software it can monitor for newly exploited vulnerabilities.
            </p>
          </div>
        ) : (
          items.map((a) => (
            <div
              key={a.id}
              className={cn(
                'flex items-center gap-3 rounded-md border px-4 py-3',
                severityBg(a.severity ?? 'high'),
              )}
            >
              <ShieldAlert className={cn('w-4 h-4 shrink-0', severityColor(a.severity ?? 'high'))} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium text-white">{a.cve_id}</span>
                  <span className="text-xs px-1.5 py-0.5 rounded bg-severity-critical/15 text-severity-critical border border-severity-critical/30">
                    actively exploited
                  </span>
                  <span className={cn('text-xs uppercase tracking-wide', severityColor(a.severity ?? 'high'))}>
                    {a.severity ?? 'high'}
                  </span>
                </div>
                <p className="text-sm text-muted truncate">
                  {a.product} {a.version} · {a.assets?.name ?? 'asset'}
                </p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                {a.finding_id && (
                  <Link
                    to={`/findings/${a.finding_id}`}
                    className="text-xs text-accent hover:underline"
                  >
                    View finding
                  </Link>
                )}
                <span className="text-xs text-muted whitespace-nowrap">{timeAgo(a.created_at)}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
