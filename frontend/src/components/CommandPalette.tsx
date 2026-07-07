import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Search, CornerDownLeft, Server, AlertTriangle, Radar, LayoutDashboard,
  Eye, Clock, Activity, Lock, Users, ScrollText, Bell, Settings, Brain, type LucideIcon,
} from 'lucide-react'
import { api } from '../lib/api'
import { useRole, type Role } from '../hooks/useRole'
import { cn } from '../lib/utils'

// Event the Header (or anything else) can fire to toggle the palette.
export const PALETTE_TOGGLE_EVENT = 'commandpalette:toggle'

type Group = 'Pages' | 'Assets' | 'Findings' | 'Scans'

interface Item {
  key: string
  group: Group
  label: string
  sublabel?: string
  to: string
  icon: LucideIcon
}

const PAGES: { label: string; to: string; icon: LucideIcon; minRole?: Role }[] = [
  { label: 'Dashboard', to: '/dashboard', icon: LayoutDashboard },
  { label: 'Assets', to: '/assets', icon: Server },
  { label: 'Discovery', to: '/discovery', icon: Radar },
  { label: 'Watchtower', to: '/watchtower', icon: Eye },
  { label: 'Scans', to: '/scans', icon: Search },
  { label: 'Schedules', to: '/schedules', icon: Clock },
  { label: 'Job history', to: '/jobs', icon: Activity },
  { label: 'Findings', to: '/findings', icon: AlertTriangle },
  { label: 'Permissions', to: '/permissions', icon: Lock },
  { label: 'Team', to: '/team', icon: Users },
  { label: 'Audit log', to: '/audit', icon: ScrollText, minRole: 'admin' },
  { label: 'Integrations', to: '/integrations', icon: Bell, minRole: 'admin' },
  { label: 'Settings', to: '/settings', icon: Settings },
  { label: 'Analytics', to: '/analytics', icon: Brain },
]

interface AssetRow { id: string; name: string; host: string }
interface FindingRow { id: string; title: string; severity: string; cve_ids?: string[]; assets?: { host?: string } }
interface ScanRow { id: string; status: string; created_at: string; assets?: { name?: string; host?: string } }

const MAX_PER_GROUP = 6

export function CommandPalette() {
  const navigate = useNavigate()
  const { can } = useRole()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const [loaded, setLoaded] = useState(false)
  const [assets, setAssets] = useState<AssetRow[]>([])
  const [findings, setFindings] = useState<FindingRow[]>([])
  const [scans, setScans] = useState<ScanRow[]>([])
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  // Open with ⌘K / Ctrl-K, plus a custom event the Header trigger fires.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setOpen((o) => !o)
      }
      if (e.key === 'Escape') {
        setOpen(false)
      }
    }
    const onToggle = () => setOpen((o) => !o)
    window.addEventListener('keydown', onKey)
    window.addEventListener(PALETTE_TOGGLE_EVENT, onToggle)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener(PALETTE_TOGGLE_EVENT, onToggle)
    }
  }, [])

  // Lazy-load the searchable data the first time the palette opens.
  useEffect(() => {
    if (!open || loaded) return
    setLoaded(true)
    Promise.allSettled([
      api.get<AssetRow[]>('/assets'),
      api.get<{ items: FindingRow[] }>('/findings'),
      api.get<ScanRow[]>('/scans'),
    ]).then(([a, f, s]) => {
      if (a.status === 'fulfilled') setAssets(a.value)
      if (f.status === 'fulfilled') setFindings(f.value.items)
      if (s.status === 'fulfilled') setScans(s.value)
    })
  }, [open, loaded])

  // Reset transient state and focus the input each time it opens.
  useEffect(() => {
    if (open) {
      setQuery('')
      setActive(0)
      requestAnimationFrame(() => inputRef.current?.focus())
    }
  }, [open])

  const items = useMemo<Item[]>(() => {
    const q = query.trim().toLowerCase()
    const pages = PAGES.filter((p) => !p.minRole || can(p.minRole))

    // With no query, the palette is a fast page switcher.
    if (!q) {
      return pages.map((p) => ({ key: `page:${p.to}`, group: 'Pages', label: p.label, to: p.to, icon: p.icon }))
    }

    const match = (s?: string | null) => (s ?? '').toLowerCase().includes(q)

    const pageItems: Item[] = pages
      .filter((p) => match(p.label))
      .map((p) => ({ key: `page:${p.to}`, group: 'Pages', label: p.label, to: p.to, icon: p.icon }))

    const assetItems: Item[] = assets
      .filter((a) => match(a.name) || match(a.host))
      .slice(0, MAX_PER_GROUP)
      .map((a) => ({ key: `asset:${a.id}`, group: 'Assets', label: a.name || a.host, sublabel: a.host, to: '/assets', icon: Server }))

    const findingItems: Item[] = findings
      .filter((f) => match(f.title) || match(f.assets?.host) || (f.cve_ids ?? []).some(match))
      .slice(0, MAX_PER_GROUP)
      .map((f) => ({
        key: `finding:${f.id}`,
        group: 'Findings',
        label: f.title,
        sublabel: [f.severity, f.assets?.host, (f.cve_ids ?? [])[0]].filter(Boolean).join(' · '),
        to: `/findings/${f.id}`,
        icon: AlertTriangle,
      }))

    const scanItems: Item[] = scans
      .filter((s) => match(s.assets?.host) || match(s.assets?.name) || match(s.status) || match(s.id))
      .slice(0, MAX_PER_GROUP)
      .map((s) => ({
        key: `scan:${s.id}`,
        group: 'Scans',
        label: s.assets?.name || s.assets?.host || s.id.slice(0, 8),
        sublabel: s.status,
        to: `/scans/${s.id}`,
        icon: Radar,
      }))

    return [...pageItems, ...assetItems, ...findingItems, ...scanItems]
  }, [query, assets, findings, scans, can])

  // Keep the active index in range and scrolled into view.
  useEffect(() => { setActive(0) }, [query])
  useEffect(() => {
    const el = listRef.current?.querySelector<HTMLElement>(`[data-idx="${active}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [active])

  const select = (item: Item | undefined) => {
    if (!item) return
    setOpen(false)
    navigate(item.to)
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') { setOpen(false); return }
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => Math.min(i + 1, items.length - 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => Math.max(i - 1, 0)) }
    else if (e.key === 'Enter') { e.preventDefault(); select(items[active]) }
  }

  if (!open) return null

  // Build group headers inline while rendering the flat, keyboard-navigable list.
  let lastGroup: Group | null = null

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 backdrop-blur-sm pt-[12vh] px-4"
      onMouseDown={() => setOpen(false)}
    >
      <div
        className="w-full max-w-xl glass border border-white/10 rounded-xl shadow-2xl overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
        onKeyDown={onKeyDown}
      >
        <div className="flex items-center gap-2 px-4 border-b border-white/10">
          <Search className="w-4 h-4 text-white/60 shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search assets, findings, scans…"
            className="flex-1 bg-transparent py-3 text-sm text-white placeholder:text-white/60 focus:outline-none"
          />
          <kbd className="text-[10px] text-white/60 border border-white/10 bg-white/5 rounded px-1.5 py-0.5">ESC</kbd>
        </div>

        <div ref={listRef} className="max-h-[55vh] overflow-y-auto py-2">
          {items.length === 0 ? (
            <p className="px-4 py-6 text-center text-sm text-white/60">No results for “{query}”.</p>
          ) : (
            items.map((item, idx) => {
              const header = item.group !== lastGroup ? item.group : null
              lastGroup = item.group
              const Icon = item.icon
              return (
                <div key={item.key}>
                  {header && (
                    <div className="px-4 pt-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-white/60">
                      {header}
                    </div>
                  )}
                  <button
                    data-idx={idx}
                    onMouseEnter={() => setActive(idx)}
                    onClick={() => select(item)}
                    className={cn(
                      'w-full flex items-center gap-3 px-4 py-2 text-left',
                      idx === active ? 'bg-horus-lapis' : 'hover:bg-white/5',
                    )}
                  >
                    <Icon className={cn('w-4 h-4 shrink-0', idx === active ? 'text-white' : 'text-white/60')} />
                    <span className="flex-1 min-w-0 truncate text-sm text-white">{item.label}</span>
                    {item.sublabel && (
                      <span className={cn('shrink-0 text-xs truncate max-w-[40%]', idx === active ? 'text-white/80' : 'text-white/40')}>{item.sublabel}</span>
                    )}
                    {idx === active && <CornerDownLeft className="w-3.5 h-3.5 text-white/80 shrink-0" />}
                  </button>
                </div>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}
