import { useEffect, useState, useRef } from 'react'
import { createPortal } from 'react-dom'
import { Link } from 'react-router-dom'
import { Eye, RefreshCw, ShieldAlert, X, Zap, AlertTriangle, Search, Shield } from 'lucide-react'
import { api, friendlyErrorMessage, ransomwareApi, RansomwareVictim, intelApi, IntelRecord, threatFeedsApi, IOCCheckResult } from '../lib/api'
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

  // Ransomware monitoring state
  const [ransomwareVictims, setRansomwareVictims] = useState<RansomwareVictim[]>([])
  const [ransomwareLoading, setRansomwareLoading] = useState(true)
  const [ransomwareCheckRunning, setRansomwareCheckRunning] = useState(false)

  // Progress modal state
  const [running, setRunning] = useState(false)
  const [progressLogs, setProgressLogs] = useState<string[]>([])
  const logsEndRef = useRef<HTMLDivElement>(null)

  // Dark web intelligence state
  const [intelSearchTerm, setIntelSearchTerm] = useState('')
  const [intelSearchType, setIntelSearchType] = useState<'domain' | 'ip' | 'email'>('domain')
  const [intelResults, setIntelResults] = useState<IntelRecord[]>([])
  const [intelLoading, setIntelLoading] = useState(false)
  const [intelError, setIntelError] = useState<string | null>(null)
  const [intelConfigured, setIntelConfigured] = useState(true)

  // IOC Intelligence state (ThreatFox + URLhaus)
  const [iocSearchTerm, setIocSearchTerm] = useState('')
  const [iocResult, setIocResult] = useState<IOCCheckResult | null>(null)
  const [iocLoading, setIocLoading] = useState(false)
  const [iocError, setIocError] = useState<string | null>(null)
  const [iocCheckRunning, setIocCheckRunning] = useState(false)

  const load = () => {
    setLoading(true)
    api.get<Alert[]>('/watchtower/alerts').then(setItems).finally(() => setLoading(false))
  }

  const loadRansomware = () => {
    setRansomwareLoading(true)
    ransomwareApi.listVictims().then(setRansomwareVictims).catch(() => setRansomwareVictims([])).finally(() => setRansomwareLoading(false))
  }

  useEffect(load, [])
  useEffect(loadRansomware, [])

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

  const searchIntelX = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!intelSearchTerm.trim()) return

    setIntelLoading(true)
    setIntelError(null)
    setIntelResults([])

    try {
      const result = await intelApi.search(intelSearchTerm, intelSearchType)
      setIntelResults(result.results)
    } catch (err) {
      const msg = friendlyErrorMessage(err)
      if (msg.includes('not configured')) {
        setIntelConfigured(false)
      }
      setIntelError(msg)
      setIntelResults([])
    } finally {
      setIntelLoading(false)
    }
  }

  const searchIOC = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!iocSearchTerm.trim()) return

    setIocLoading(true)
    setIocError(null)
    setIocResult(null)

    try {
      const result = await threatFeedsApi.checkIOC(iocSearchTerm)
      setIocResult(result)
    } catch (err) {
      const msg = friendlyErrorMessage(err)
      setIocError(msg)
      setIocResult(null)
    } finally {
      setIocLoading(false)
    }
  }

  const scanAssetsForIOC = async () => {
    setIocCheckRunning(true)
    try {
      await threatFeedsApi.scanAssets()
      // Optionally reload findings or show success message
    } catch (err) {
      const msg = friendlyErrorMessage(err)
      setIocError(msg)
    } finally {
      setIocCheckRunning(false)
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

      {/* Ransomware Monitoring Section */}
      <div className="border-t border-white/10 pt-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-severity-critical" />
            <h2 className="text-lg font-semibold">Ransomware Monitoring</h2>
          </div>
          {can('admin') && (
            <button
              onClick={async () => {
                setRansomwareCheckRunning(true)
                try {
                  await ransomwareApi.checkNow()
                  await loadRansomware()
                } catch (e) {
                  console.error('Ransomware check failed:', e)
                } finally {
                  setRansomwareCheckRunning(false)
                }
              }}
              disabled={ransomwareCheckRunning}
              className="flex items-center gap-1.5 text-sm bg-severity-critical/10 text-severity-critical px-3 py-1.5 rounded-md hover:bg-severity-critical/20 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={cn('w-4 h-4', ransomwareCheckRunning && 'animate-spin')} />
              Check now
            </button>
          )}
        </div>

        <p className="text-sm text-muted mb-4">
          Deep web monitoring: check your assets against the Ransomware.live victim database.
          Ransomware groups publish victim names and details when they demand payment or extort data.
          Early detection enables containment and response.
        </p>

        <div className="space-y-2">
          {ransomwareLoading ? (
            <div className="text-xs text-muted py-8 text-center">Loading…</div>
          ) : !ransomwareVictims.length ? (
            <div className="flex flex-col items-center gap-2 text-center py-8 text-muted">
              <Zap className="w-8 h-8 opacity-40" />
              <p className="text-sm">No ransomware group mentions found for your assets.</p>
            </div>
          ) : (
            ransomwareVictims.map((v) => (
              <div
                key={v.id}
                className="flex items-center gap-3 rounded-md border border-severity-critical/30 bg-severity-critical/5 px-4 py-3"
              >
                <Zap className="w-4 h-4 shrink-0 text-severity-critical" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium text-white">{v.raw_data.group}</span>
                    <span className="text-xs px-1.5 py-0.5 rounded bg-severity-critical/15 text-severity-critical border border-severity-critical/30">
                      ransomware victim
                    </span>
                  </div>
                  <p className="text-sm text-muted">
                    {v.raw_data.victim || v.raw_data.website}
                  </p>
                  {v.raw_data.discovered_at && (
                    <p className="text-xs text-muted/60 mt-1">
                      Discovered: {new Date(v.raw_data.discovered_at).toLocaleDateString()}
                    </p>
                  )}
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  {v.raw_data.leak_url && (
                    <a
                      href={v.raw_data.leak_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-accent hover:underline"
                    >
                      Leak site
                    </a>
                  )}
                  <span className="text-xs text-muted whitespace-nowrap">{timeAgo(v.first_seen_at)}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Dark Web Intelligence Section */}
      <div className="border-t border-white/10 pt-6">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="w-5 h-5 text-amber-500" />
          <h2 className="text-lg font-semibold">Dark Web Intelligence</h2>
        </div>

        {!intelConfigured && (
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-md px-4 py-3 mb-4 flex items-center gap-3">
            <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
            <div className="flex-1">
              <p className="text-sm text-amber-100">IntelligenceX API key not configured.</p>
              <p className="text-xs text-amber-100/70 mt-1">
                <Link to="/settings" className="text-amber-400 hover:underline">
                  Configure it in Settings
                </Link>
                {' '}to search dark web sources for mentions of your domains, IPs, and emails.
              </p>
            </div>
          </div>
        )}

        <form onSubmit={searchIntelX} className="mb-4">
          <div className="flex gap-2 flex-wrap">
            <input
              type="text"
              value={intelSearchTerm}
              onChange={(e) => setIntelSearchTerm(e.target.value)}
              placeholder="Enter domain, IP, or email..."
              className="flex-1 min-w-[200px] px-3 py-2 rounded-md bg-white/5 border border-white/10 text-white placeholder:text-muted focus:outline-none focus:border-accent/50 transition-colors text-sm"
            />
            <select
              value={intelSearchType}
              onChange={(e) => setIntelSearchType(e.target.value as any)}
              className="px-3 py-2 rounded-md bg-white/5 border border-white/10 text-white focus:outline-none focus:border-accent/50 transition-colors text-sm"
            >
              <option value="domain">Domain</option>
              <option value="ip">IP</option>
              <option value="email">Email</option>
            </select>
            <button
              type="submit"
              disabled={intelLoading || !intelConfigured}
              className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-2 rounded-md hover:bg-accent/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Search className={cn('w-4 h-4', intelLoading && 'animate-spin')} />
              Search
            </button>
          </div>
        </form>

        {intelError && (
          <div className="bg-severity-critical/10 border border-severity-critical/30 rounded-md px-4 py-3 mb-4">
            <p className="text-sm text-severity-critical">{intelError}</p>
          </div>
        )}

        {intelResults.length > 0 ? (
          <div className="space-y-2">
            <p className="text-xs text-muted mb-3">
              Found {intelResults.length} mention{intelResults.length !== 1 ? 's' : ''}
              {intelResults.some(r => r.bucket?.toLowerCase().includes('dark')) &&
                ` (${intelResults.filter(r => r.bucket?.toLowerCase().includes('dark')).length} on dark web)`}
            </p>
            {intelResults.map((record, idx) => {
              const isDarkweb = record.bucket?.toLowerCase().includes('dark') ||
                                record.bucket?.toLowerCase().includes('leak') ||
                                record.bucket?.toLowerCase().includes('paste') ||
                                record.bucket?.toLowerCase().includes('tor') ||
                                record.bucket?.toLowerCase().includes('i2p')
              return (
                <div
                  key={idx}
                  className="flex items-start gap-3 rounded-md border border-white/10 bg-white/[0.02] px-4 py-3 hover:border-white/20 transition-colors"
                >
                  {isDarkweb && (
                    <span className="text-xs px-2 py-1 rounded bg-severity-critical/20 text-severity-critical border border-severity-critical/30 whitespace-nowrap mt-0.5">
                      DARK WEB
                    </span>
                  )}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-white break-words">{record.name}</p>
                    <p className="text-xs text-muted mt-1">
                      {record.bucket}
                      {record.date && ` • ${new Date(record.date).toLocaleDateString()}`}
                    </p>
                  </div>
                </div>
              )
            })}
          </div>
        ) : intelLoading ? (
          <div className="flex items-center justify-center py-8 text-muted">
            <RefreshCw className="w-4 h-4 animate-spin mr-2" />
            Searching dark web sources...
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2 text-center py-8 text-muted">
            <Search className="w-8 h-8 opacity-40" />
            <p className="text-sm">Enter a domain, IP, or email to search dark web sources.</p>
            <p className="text-xs max-w-md">
              Results include mentions on Tor, I2P, Pastebin, and other dark web leaks.
            </p>
          </div>
        )}
      </div>

      {/* IOC Intelligence Section (ThreatFox + URLhaus) */}
      <div className="border-t border-white/10 pt-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-amber-500" />
            <h2 className="text-lg font-semibold">IOC Intelligence (ThreatFox + URLhaus)</h2>
          </div>
          {can('admin') && (
            <button
              onClick={scanAssetsForIOC}
              disabled={iocCheckRunning}
              className="flex items-center gap-1.5 text-sm bg-amber-500/10 text-amber-500 px-3 py-1.5 rounded-md hover:bg-amber-500/20 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={cn('w-4 h-4', iocCheckRunning && 'animate-spin')} />
              Scan all assets
            </button>
          )}
        </div>

        <p className="text-sm text-muted mb-4">
          Check your assets against abuse.ch's ThreatFox (C2, malware IOCs) and URLhaus
          (malicious URL hosting) databases. No authentication required.
        </p>

        <form onSubmit={searchIOC} className="mb-4">
          <div className="flex gap-2">
            <input
              type="text"
              value={iocSearchTerm}
              onChange={(e) => setIocSearchTerm(e.target.value)}
              placeholder="Enter domain or IP to check IOC status..."
              className="flex-1 px-3 py-2 rounded-md bg-white/5 border border-white/10 text-white placeholder:text-muted focus:outline-none focus:border-accent/50 transition-colors text-sm"
            />
            <button
              type="submit"
              disabled={iocLoading}
              className="flex items-center gap-1.5 text-sm bg-amber-500/10 text-amber-500 px-3 py-2 rounded-md hover:bg-amber-500/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Search className={cn('w-4 h-4', iocLoading && 'animate-spin')} />
              Check
            </button>
          </div>
        </form>

        {iocError && (
          <div className="bg-severity-critical/10 border border-severity-critical/30 rounded-md px-4 py-3 mb-4">
            <p className="text-sm text-severity-critical">{iocError}</p>
          </div>
        )}

        {iocResult ? (
          <div className="space-y-4">
            <p className="text-xs text-muted">
              Checked: <span className="text-white font-medium">{iocResult.term}</span>
            </p>

            {/* ThreatFox Results */}
            <div className="border border-white/10 rounded-md p-4 bg-white/[0.02]">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-4 h-4 text-amber-500" />
                <h3 className="text-sm font-medium">ThreatFox</h3>
                {iocResult.threatfox.found && (
                  <span className="ml-auto text-xs px-2 py-1 rounded bg-severity-critical/20 text-severity-critical border border-severity-critical/30">
                    {iocResult.threatfox.threats.length} threat(s)
                  </span>
                )}
              </div>
              {iocResult.threatfox.found && iocResult.threatfox.threats.length > 0 ? (
                <div className="space-y-2">
                  {iocResult.threatfox.threats.map((threat, idx) => (
                    <div key={idx} className="text-sm rounded-md bg-severity-critical/5 border border-severity-critical/30 px-3 py-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-medium text-white">{threat.threat_type}</span>
                        {threat.malware && (
                          <span className="text-xs px-1.5 py-0.5 rounded bg-severity-critical/15 text-severity-critical border border-severity-critical/30">
                            {threat.malware}
                          </span>
                        )}
                        <span className="text-xs text-muted ml-auto">
                          {threat.confidence_level}% confidence
                        </span>
                      </div>
                      {threat.reference && (
                        <p className="text-xs text-muted/70 mt-1 truncate">
                          <a href={threat.reference} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                            View on ThreatFox
                          </a>
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted">Not listed in ThreatFox</p>
              )}
            </div>

            {/* URLhaus Results */}
            <div className="border border-white/10 rounded-md p-4 bg-white/[0.02]">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-4 h-4 text-blue-500" />
                <h3 className="text-sm font-medium">URLhaus</h3>
                {iocResult.urlhaus.found && (
                  <span className="ml-auto text-xs px-2 py-1 rounded bg-severity-high/20 text-severity-high border border-severity-high/30">
                    {iocResult.urlhaus.urls.length} URL(s)
                  </span>
                )}
              </div>
              {iocResult.urlhaus.found && iocResult.urlhaus.urls.length > 0 ? (
                <div className="space-y-2">
                  {iocResult.urlhaus.urls.map((url, idx) => (
                    <div key={idx} className="text-sm rounded-md bg-severity-high/5 border border-severity-high/30 px-3 py-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs px-1.5 py-0.5 rounded bg-severity-high/15 text-severity-high border border-severity-high/30">
                          {url.threat}
                        </span>
                        <span className={cn('text-xs',
                          url.url_status === 'online' ? 'text-severity-critical' : 'text-muted'
                        )}>
                          {url.url_status}
                        </span>
                      </div>
                      <p className="text-xs text-muted/70 mt-1 truncate">
                        <a href={url.urlhaus_link} target="_blank" rel="noopener noreferrer" className="text-accent hover:underline">
                          {url.url}
                        </a>
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted">Not hosting malicious URLs in URLhaus</p>
              )}
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2 text-center py-8 text-muted">
            <Shield className="w-8 h-8 opacity-40" />
            <p className="text-sm">Enter a domain or IP to check against ThreatFox and URLhaus IOC databases.</p>
          </div>
        )}
      </div>
    </div>
  )
}
