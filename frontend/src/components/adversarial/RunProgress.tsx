import { useEffect, useRef, useState } from 'react'
import {
  Swords, Shield, X, Loader2, CheckCircle, XCircle,
  ChevronRight, ShieldAlert, Minimize2, Maximize2, Brain,
} from 'lucide-react'
import { supabase } from '../../lib/supabase'
import { cn, severityBg, severityColor } from '../../lib/utils'

interface AgentEvent {
  type: string
  agent?: 'red' | 'blue' | 'system'
  tool?: string
  subject?: string
  ok?: boolean
  title?: string
  severity?: string
  category?: string
  effort?: string
  count?: number
  text?: string
  final?: boolean
  findings_created?: number
  responses_created?: number
  message?: string
  ts: string
}

const TOOL_LABELS: Record<string, string> = {
  check_dns_security:       'DNS security',
  check_exposed_paths:      'Exposed paths',
  check_security_headers:   'Security headers',
  check_ssl_tls:            'TLS / SSL',
  enumerate_subdomains:     'Subdomains',
  lookup_exploits:          'Exploit lookup',
  hibp_domain_check:        'Breach check',
  web_search:               'Web search',
  get_asset_findings:       'Asset findings',
  save_red_finding:         'Save finding',
  get_pending_red_findings: 'Pending findings',
  get_cve_details:          'CVE details',
  respond_to_finding:       'Write response',
}

function ThoughtBlock({ text, final }: { text: string; final: boolean }) {
  const [expanded, setExpanded] = useState(false)
  const isLong = text.length > 260
  const preview = isLong && !expanded ? text.slice(0, 260).trimEnd() + '…' : text

  return (
    <div className="flex gap-2 px-3 py-1.5 my-0.5">
      <div className={cn('w-px rounded self-stretch shrink-0', final ? 'bg-horus-gold/30' : 'bg-white/10')} />
      <div className="flex-1 min-w-0">
        <p className={cn(
          'text-[11px] leading-relaxed whitespace-pre-wrap break-words',
          final ? 'text-white/60' : 'text-white/40',
        )}>
          {preview}
        </p>
        {isLong && (
          <button
            onClick={() => setExpanded((e) => !e)}
            className="text-[10px] text-accent/60 hover:text-accent mt-0.5 transition-colors"
          >
            {expanded ? 'Show less' : 'Show more'}
          </button>
        )}
      </div>
    </div>
  )
}

function EventRow({ event }: { event: AgentEvent }) {
  const isRed = event.agent === 'red'

  switch (event.type) {
    case 'agent_start':
      return (
        <div className={cn(
          'flex items-center gap-2 px-3 py-1.5 border-t border-white/5 mt-1',
          isRed ? 'text-severity-critical/80' : 'text-mode-auto/80',
        )}>
          {isRed ? <Swords className="w-3 h-3 shrink-0" /> : <Shield className="w-3 h-3 shrink-0" />}
          <span className="text-[10px] uppercase tracking-widest font-semibold">
            {isRed ? 'Red Agent' : 'Blue Agent'}
          </span>
        </div>
      )

    case 'model_thought':
      return <ThoughtBlock text={event.text ?? ''} final={!!event.final} />

    case 'tool_call':
      return (
        <div className="flex items-center gap-1.5 px-3 py-0.5 text-white/50">
          <ChevronRight className="w-3 h-3 shrink-0 text-white/25" />
          <span className={cn('shrink-0 text-[11px]', isRed ? 'text-severity-critical/60' : 'text-mode-auto/60')}>
            {TOOL_LABELS[event.tool ?? ''] ?? event.tool}
          </span>
          {event.subject && (
            <span className="truncate text-[11px] text-white/30">· {event.subject}</span>
          )}
        </div>
      )

    case 'tool_result':
      return (
        <div className={cn(
          'flex items-center gap-1.5 px-3 py-0.5 text-[11px]',
          event.ok ? 'text-white/20' : 'text-severity-critical/60',
        )}>
          <span className="ml-3">{event.ok ? '✓' : '✗'}</span>
        </div>
      )

    case 'finding_saved':
      return (
        <div className="flex items-center gap-2 px-3 py-1 mx-2 my-0.5 bg-severity-critical/5 rounded border border-severity-critical/15">
          <ShieldAlert className="w-3 h-3 text-severity-critical shrink-0" />
          <span className="flex-1 truncate text-[11px] text-horus-ivory">{event.title}</span>
          <span className={cn(
            'text-[9px] px-1.5 py-0.5 rounded uppercase font-medium shrink-0',
            severityBg(event.severity ?? ''),
            severityColor(event.severity ?? ''),
          )}>
            {event.severity}
          </span>
        </div>
      )

    case 'response_saved':
      return (
        <div className="flex items-center gap-2 px-3 py-1 mx-2 my-0.5 bg-mode-auto/5 rounded border border-mode-auto/15">
          <Shield className="w-3 h-3 text-mode-auto shrink-0" />
          <span className="flex-1 truncate text-[11px] text-white/70">Response written</span>
          {event.effort && <span className="text-[9px] text-mode-auto shrink-0">{event.effort}</span>}
        </div>
      )

    case 'agent_done':
      return (
        <div className={cn(
          'flex items-center gap-2 px-3 py-1 border-b border-white/5 mb-1 text-[10px] uppercase tracking-wider',
          isRed ? 'text-severity-critical/60' : 'text-mode-auto/60',
        )}>
          <CheckCircle className="w-3 h-3 shrink-0" />
          <span>
            {event.agent === 'red'
              ? `Red done — ${event.count} finding${event.count !== 1 ? 's' : ''}`
              : `Blue done — ${event.count} response${event.count !== 1 ? 's' : ''}`}
          </span>
        </div>
      )

    case 'error':
      return (
        <div className="flex items-center gap-2 px-3 py-1 text-severity-critical/70 text-[11px]">
          <XCircle className="w-3 h-3 shrink-0" />
          <span className="truncate">{event.message}</span>
        </div>
      )

    default:
      return null
  }
}

interface RunProgressProps {
  runId: string
  isLive?: boolean
  title?: string
  onClose: () => void
  onDone?: () => void
}

export function RunProgress({ runId, isLive = true, title, onClose, onDone }: RunProgressProps) {
  const [events, setEvents]           = useState<AgentEvent[]>([])
  const [isDone, setIsDone]           = useState(false)
  const [streamError, setStreamError] = useState('')
  const [minimized, setMinimized]     = useState(false)
  const scrollRef    = useRef<HTMLDivElement>(null)
  const calledOnDone = useRef(false)

  const findingsCount  = events.filter((e) => e.type === 'finding_saved').length
  const responsesCount = events.filter((e) => e.type === 'response_saved').length
  const redStarted = events.some((e) => e.type === 'agent_start' && e.agent === 'red')
  const blueStarted = events.some((e) => e.type === 'agent_start' && e.agent === 'blue')
  const redDone    = events.some((e) => e.type === 'agent_done'  && e.agent === 'red')
  const blueDone   = events.some((e) => e.type === 'agent_done'  && e.agent === 'blue')

  useEffect(() => {
    const controller = new AbortController()

    async function stream() {
      const { data } = await supabase.auth.getSession()
      const token = data.session?.access_token
      if (!token) { setStreamError('No session'); return }

      try {
        const res = await fetch(`/api/adversarial/runs/${runId}/stream`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        })
        if (!res.ok || !res.body) { setStreamError(`Stream error: ${res.status}`); return }

        const reader  = res.body.getReader()
        const decoder = new TextDecoder()
        let buffer = ''

        while (true) {
          const { value, done } = await reader.read()
          if (done) break

          buffer += decoder.decode(value, { stream: true })
          const lines = buffer.split('\n')
          buffer = lines.pop() ?? ''

          for (const line of lines) {
            if (!line.startsWith('data: ')) continue
            const payload = line.slice(6).trim()
            if (!payload) continue
            try {
              const event: AgentEvent = JSON.parse(payload)
              setEvents((prev) => [...prev, event])
              if (event.type === 'done') { setIsDone(true); return }
            } catch { /* ignore malformed */ }
          }
        }
        setIsDone(true)
      } catch (e) {
        if ((e as Error).name !== 'AbortError') setStreamError((e as Error).message)
      }
    }

    stream()
    return () => controller.abort()
  }, [runId])

  useEffect(() => {
    if (isDone && !calledOnDone.current) {
      calledOnDone.current = true
      onDone?.()
    }
  }, [isDone, onDone])

  useEffect(() => {
    if (!minimized && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [events, minimized])

  const headerTitle = title ?? (isLive ? 'Adversarial Cycle' : 'Run Log')

  // ── Minimized pill ─────────────────────────────────────────────────────────
  if (minimized) {
    return (
      <div className="fixed bottom-5 right-5 z-50">
        <div
          className="glass border border-white/10 shadow-2xl rounded-xl flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-white/5 transition-colors"
          onClick={() => setMinimized(false)}
        >
          <Swords className="w-4 h-4 text-horus-gold shrink-0" />
          <div className="flex flex-col leading-tight">
            <span className="text-xs font-medium text-horus-ivory">{headerTitle}</span>
            <span className="text-[10px] text-white/40">
              {isDone
                ? `Done — ${findingsCount} findings, ${responsesCount} responses`
                : `Running… ${findingsCount} finding${findingsCount !== 1 ? 's' : ''} so far`}
            </span>
          </div>
          {!isDone
            ? <Loader2 className="w-3.5 h-3.5 text-accent animate-spin shrink-0" />
            : <CheckCircle className="w-3.5 h-3.5 text-mode-auto shrink-0" />}
          <Maximize2 className="w-3.5 h-3.5 text-white/30 shrink-0 ml-1" />
        </div>
      </div>
    )
  }

  // ── Full modal ─────────────────────────────────────────────────────────────
  return (
    <>
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40"
        onClick={() => setMinimized(true)}
      />

      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
        <div className="glass border border-white/10 rounded-xl shadow-2xl w-full max-w-[600px] flex flex-col max-h-[75vh] pointer-events-auto">

          {/* Title bar */}
          <div className="flex items-center gap-3 px-5 py-3.5 border-b border-white/10 shrink-0">
            <Swords className="w-4 h-4 text-horus-gold shrink-0" />
            <span className="text-sm font-semibold flex-1 truncate">{headerTitle}</span>
            <div className="flex items-center gap-1.5 mr-2">
              {isDone
                ? <CheckCircle className="w-3.5 h-3.5 text-mode-auto" />
                : <Loader2 className="w-3.5 h-3.5 text-accent animate-spin" />}
              <span className={cn('text-xs', isDone ? 'text-mode-auto' : 'text-accent')}>
                {isDone ? 'Done' : 'Running…'}
              </span>
            </div>
            {isLive && (
              <button
                onClick={() => setMinimized(true)}
                className="text-white/40 hover:text-white transition-colors p-1 rounded"
                title="Minimise"
              >
                <Minimize2 className="w-3.5 h-3.5" />
              </button>
            )}
            <button
              onClick={onClose}
              className="text-white/40 hover:text-white transition-colors p-1 rounded"
              title="Close"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Agent status bar */}
          <div className="flex divide-x divide-white/10 border-b border-white/10 shrink-0">
            <div className={cn('flex-1 flex items-center gap-2 px-5 py-2.5', !redStarted && 'opacity-40')}>
              <div className={cn(
                'w-1.5 h-1.5 rounded-full shrink-0',
                redStarted && !redDone ? 'bg-severity-critical animate-pulse'
                  : redDone              ? 'bg-severity-critical/40'
                  :                        'bg-white/20',
              )} />
              <Swords className="w-3 h-3 text-severity-critical/60 shrink-0" />
              <span className="text-xs text-white/60">Red Agent</span>
              <span className="text-xs text-severity-critical font-mono ml-auto">
                {findingsCount} finding{findingsCount !== 1 ? 's' : ''}
              </span>
            </div>
            <div className={cn('flex-1 flex items-center gap-2 px-5 py-2.5', !blueStarted && 'opacity-40')}>
              <div className={cn(
                'w-1.5 h-1.5 rounded-full shrink-0',
                blueStarted && !blueDone ? 'bg-mode-auto animate-pulse'
                  : blueDone              ? 'bg-mode-auto/40'
                  :                         'bg-white/20',
              )} />
              <Shield className="w-3 h-3 text-mode-auto/60 shrink-0" />
              <span className="text-xs text-white/60">Blue Agent</span>
              <span className="text-xs text-mode-auto font-mono ml-auto">
                {responsesCount} response{responsesCount !== 1 ? 's' : ''}
              </span>
            </div>
          </div>

          {/* Event log */}
          <div ref={scrollRef} className="flex-1 overflow-y-auto py-2 font-mono text-xs min-h-0">
            {events.length === 0 && !streamError && (
              <div className="flex items-center gap-2 px-4 py-3 text-white/30">
                <Loader2 className="w-3 h-3 animate-spin" />
                <span>Connecting to agent…</span>
              </div>
            )}

            {events.map((event, i) => <EventRow key={i} event={event} />)}

            {!isDone && events.length > 0 && !streamError && (
              <div className="flex items-center gap-2 px-3 py-1.5 text-white/20">
                <Brain className="w-3 h-3 animate-pulse" />
                <span>agent thinking…</span>
              </div>
            )}

            {streamError && (
              <div className="flex items-center gap-2 px-4 py-2 mx-3 mt-2 bg-severity-critical/10 rounded border border-severity-critical/20 text-severity-critical text-[11px]">
                <XCircle className="w-3.5 h-3.5 shrink-0" />
                <span>{streamError}</span>
              </div>
            )}
          </div>

          {/* Footer */}
          {isDone && (
            <div className="border-t border-white/10 px-5 py-3 flex items-center gap-3 shrink-0">
              <CheckCircle className="w-4 h-4 text-mode-auto shrink-0" />
              <span className="text-xs text-white/60 flex-1">
                Cycle complete — <span className="text-severity-critical">{findingsCount} finding{findingsCount !== 1 ? 's' : ''}</span>
                {' · '}
                <span className="text-mode-auto">{responsesCount} response{responsesCount !== 1 ? 's' : ''}</span>
              </span>
              <button
                onClick={onClose}
                className="text-xs px-3 py-1.5 rounded bg-horus-lapis text-white hover:bg-horus-lapis/80 transition-colors"
              >
                Close
              </button>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
