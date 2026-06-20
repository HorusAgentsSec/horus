import { useEffect, useRef, useState } from 'react'
import { X, Sparkles, Loader2 } from 'lucide-react'
import { api, friendlyErrorMessage } from '../../lib/api'

interface Analysis {
  analyzed: number
  groups: number
  system?: string | null
  prompt: string | null
  response: string | null
  model: string | null
  tokens_in?: number | null
  tokens_out?: number | null
  message?: string
}

interface Props {
  agentId: string
  agentName: string
  onClose: () => void
}

const POLL_MS = 12000

export function IrisAiModal({ agentId, agentName, onClose }: Props) {
  const [data, setData] = useState<Analysis | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<string | null>(null)
  const alive = useRef(true)

  useEffect(() => {
    alive.current = true
    const load = async () => {
      setRefreshing(true)
      try {
        // ttlMs=0 bypasses the GET cache so each poll is fresh
        const res = await api.get<Analysis>(`/iris/agents/${agentId}/ai-analysis`, 0)
        if (!alive.current) return
        setData(res)
        setError(null)
        setLastUpdated(new Date().toLocaleTimeString())
      } catch (e: unknown) {
        if (alive.current) setError(friendlyErrorMessage(e, 'Analysis failed'))
      } finally {
        if (alive.current) setRefreshing(false)
      }
    }
    load()
    const id = setInterval(load, POLL_MS)
    return () => { alive.current = false; clearInterval(id) }
  }, [agentId])

  // Close on Escape
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const verdict = (() => {
    if (!data?.response) return null
    try {
      const arr = JSON.parse(data.response.trim().replace(/^```json/, '').replace(/^```/, '').replace(/```$/, '').trim())
      return Array.isArray(arr) ? arr : null
    } catch { return null }
  })()

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="bg-surface border border-border rounded-lg w-full max-w-2xl max-h-[85vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-accent" />
            <div>
              <h2 className="text-sm font-semibold text-white">Iris AI live triage</h2>
              <p className="text-xs text-muted">{agentName}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {refreshing && <Loader2 className="w-3.5 h-3.5 text-muted animate-spin" />}
            <button onClick={onClose} className="p-1 hover:bg-border rounded transition text-muted hover:text-white">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="overflow-y-auto px-6 py-4 space-y-4 text-sm">
          {error && (
            <div className="border border-severity-critical/40 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical rounded">
              {error}
            </div>
          )}

          {!data && !error && (
            <p className="text-muted">Analyzing…</p>
          )}

          {data?.message && (
            <p className="text-muted">{data.message}</p>
          )}

          {data && !data.message && (
            <>
              {/* Stats */}
              <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-muted">
                <span><span className="text-white">{data.analyzed}</span> recent events</span>
                <span><span className="text-white">{data.groups}</span> groups</span>
                {data.model && <span>model <span className="text-white font-mono">{data.model}</span></span>}
                {data.tokens_in != null && (
                  <span>tokens <span className="text-white">{data.tokens_in}→{data.tokens_out}</span></span>
                )}
              </div>

              {/* AI verdict */}
              <div>
                <p className="text-xs text-muted uppercase tracking-wide mb-1.5">AI verdict</p>
                {verdict && verdict.length === 0 && (
                  <p className="text-success text-sm">No threats. All activity looks like routine noise.</p>
                )}
                {verdict && verdict.length > 0 && (
                  <div className="space-y-2">
                    {verdict.map((v: { group?: string; risk?: string; reason?: string }, i: number) => (
                      <div key={i} className="border border-severity-high/40 bg-severity-high/10 rounded px-3 py-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-severity-high">{v.risk}</span>
                          <span className="text-xs font-mono text-white">{v.group}</span>
                        </div>
                        <p className="text-xs text-muted mt-1">{v.reason}</p>
                      </div>
                    ))}
                  </div>
                )}
                {!verdict && data.response && (
                  <pre className="text-xs text-white bg-bg border border-border rounded p-3 overflow-x-auto whitespace-pre-wrap">{data.response}</pre>
                )}
              </div>

              {/* What the AI saw */}
              {data.prompt && (
                <details className="group">
                  <summary className="text-xs text-muted uppercase tracking-wide cursor-pointer hover:text-white">
                    Prompt sent to AI
                  </summary>
                  <pre className="mt-1.5 text-xs text-muted bg-bg border border-border rounded p-3 overflow-x-auto whitespace-pre-wrap">{data.prompt}</pre>
                </details>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-border flex items-center justify-between text-xs text-muted">
          <span>Read-only. No events processed, no findings created.</span>
          {lastUpdated && <span>updated {lastUpdated} · auto-refresh {POLL_MS / 1000}s</span>}
        </div>
      </div>
    </div>
  )
}
