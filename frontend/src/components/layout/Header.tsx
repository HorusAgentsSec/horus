import { useEffect, useState, type MouseEvent } from 'react'
import * as Popover from '@radix-ui/react-popover'
import { Bell, LogOut, Menu, Search, X } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../../hooks/useAuth'
import { api } from '../../lib/api'
import { PALETTE_TOGGLE_EVENT } from '../CommandPalette'

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)

interface Notification {
  id: string
  type: string
  title: string
  body: string | null
  metadata: Record<string, any>
  created_at: string
}

export function Header({ onMenuClick }: { onMenuClick: () => void }) {
  const { user, signOut } = useAuth()
  const navigate = useNavigate()
  const [items, setItems] = useState<Notification[]>([])
  const [open, setOpen] = useState(false)

  const load = () => {
    api.get<Notification[]>('/notifications').then(setItems).catch(() => {})
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 60_000) // poll for new alerts
    return () => clearInterval(t)
  }, [])

  const openNotification = async (n: Notification) => {
    setItems((list) => list.filter((x) => x.id !== n.id))
    api.patch(`/notifications/${n.id}/read`).catch(() => {})
    setOpen(false)
    const scanId = n.metadata?.scan_id
    if (scanId) navigate(`/scans/${scanId}`)
  }

  const dismissNotification = (e: MouseEvent, n: Notification) => {
    e.stopPropagation()
    setItems((list) => list.filter((x) => x.id !== n.id))
    api.delete(`/notifications/${n.id}`).catch(() => {})
  }

  return (
    <header className="h-14 glass border-b-0 border-white/10 shadow-sm flex items-center justify-between gap-3 px-4 sm:px-6 z-10 sticky top-0">
      <div className="flex items-center gap-2 min-w-0 flex-1">
        <button
          onClick={onMenuClick}
          aria-label="Open navigation"
          className="-ml-1 p-1.5 text-white/70 hover:text-white transition-colors md:hidden"
        >
          <Menu className="w-5 h-5" />
        </button>
        <button
          onClick={() => window.dispatchEvent(new Event(PALETTE_TOGGLE_EVENT))}
          className="flex items-center gap-2 w-72 max-w-full rounded-lg border border-white/10 glass px-3 py-1.5 text-sm text-white/60 hover:border-white/30 hover:text-white transition-colors"
        >
          <Search className="w-4 h-4 shrink-0" />
          <span className="flex-1 text-left truncate">Search…</span>
          <kbd className="hidden sm:inline text-[10px] border border-white/10 bg-white/5 rounded px-1.5 py-0.5">{isMac ? '⌘' : 'Ctrl'} K</kbd>
        </button>
      </div>
      <div className="flex items-center gap-3 sm:gap-4 shrink-0">
        <Popover.Root open={open} onOpenChange={setOpen}>
          <Popover.Trigger
            aria-label={`Notifications${items.length ? ` (${items.length} unread)` : ''}`}
            className="relative text-white/60 hover:text-white transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-horus-lapis rounded"
          >
            <Bell className="w-4 h-4" />
            {items.length > 0 && (
              <span className="absolute -top-1.5 -right-1.5 bg-severity-critical text-white text-[10px] leading-none rounded-full min-w-[15px] h-[15px] flex items-center justify-center px-1">
                {items.length > 9 ? '9+' : items.length}
              </span>
            )}
          </Popover.Trigger>
          <Popover.Portal>
            <Popover.Content
              align="end"
              sideOffset={8}
              className="z-50 w-80 max-w-[calc(100vw-1rem)] bg-black/90 backdrop-blur-xl border border-white/10 rounded-lg shadow-2xl overflow-hidden animate-fade-in focus:outline-none"
            >
              <div className="px-4 py-2 border-b border-white/10 text-xs font-medium text-white/60">
                Notifications
              </div>
              {!items.length ? (
                <div className="px-4 py-6 text-center text-xs text-white/60">You're all caught up.</div>
              ) : (
                <div className="max-h-96 overflow-y-auto">
                  {items.map((n) => (
                    <div
                      key={n.id}
                      className="group relative flex items-start border-b border-white/10 hover:bg-white/5 transition-colors"
                    >
                      <button
                        onClick={() => openNotification(n)}
                        className="flex-1 text-left px-4 py-3 min-w-0"
                      >
                        <p className="text-sm text-horus-ivory">{n.title}</p>
                        {n.body && <p className="text-xs text-white/60 mt-0.5">{n.body}</p>}
                        <p className="text-[10px] text-white/40 mt-1">
                          {new Date(n.created_at).toLocaleString()}
                        </p>
                      </button>
                      <button
                        onClick={(e) => dismissNotification(e, n)}
                        aria-label="Dismiss notification"
                        className="shrink-0 p-2 mt-1 mr-1 text-white/30 hover:text-white opacity-0 group-hover:opacity-100 focus-visible:opacity-100 transition-opacity rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-horus-lapis"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </Popover.Content>
          </Popover.Portal>
        </Popover.Root>

        <span className="hidden sm:inline text-xs text-white/60 max-w-[40vw] truncate">{user?.email}</span>
        <button
          onClick={signOut}
          className="text-white/60 hover:text-white transition-colors"
          title="Sign out"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </header>
  )
}
