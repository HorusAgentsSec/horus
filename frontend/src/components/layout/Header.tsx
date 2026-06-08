import { useEffect, useRef, useState } from 'react'
import { Bell, LogOut, Search } from 'lucide-react'
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

export function Header() {
  const { user, signOut } = useAuth()
  const navigate = useNavigate()
  const [items, setItems] = useState<Notification[]>([])
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  const load = () => {
    api.get<Notification[]>('/notifications').then(setItems).catch(() => {})
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 60_000) // poll for new alerts
    return () => clearInterval(t)
  }, [])

  // Close the dropdown when clicking outside it.
  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [])

  const openNotification = async (n: Notification) => {
    setItems((list) => list.filter((x) => x.id !== n.id))
    api.patch(`/notifications/${n.id}/read`).catch(() => {})
    setOpen(false)
    const scanId = n.metadata?.scan_id
    if (scanId) navigate(`/scans/${scanId}`)
  }

  return (
    <header className="h-14 glass border-b-0 border-white/10 shadow-sm flex items-center justify-between px-6 z-10 sticky top-0">
      <button
        onClick={() => window.dispatchEvent(new Event(PALETTE_TOGGLE_EVENT))}
        className="flex items-center gap-2 w-72 max-w-[40vw] rounded-lg border border-white/10 glass px-3 py-1.5 text-sm text-white/60 hover:border-white/30 hover:text-white transition-colors"
      >
        <Search className="w-4 h-4" />
        <span className="flex-1 text-left">Search…</span>
        <kbd className="text-[10px] border border-white/10 bg-white/5 rounded px-1.5 py-0.5">{isMac ? '⌘' : 'Ctrl'} K</kbd>
      </button>
      <div className="flex items-center gap-4">
        <div className="relative" ref={ref}>
          <button
            onClick={() => setOpen((o) => !o)}
            className="relative text-white/60 hover:text-white transition-colors"
          >
            <Bell className="w-4 h-4" />
            {items.length > 0 && (
              <span className="absolute -top-1.5 -right-1.5 bg-severity-critical text-white text-[10px] leading-none rounded-full min-w-[15px] h-[15px] flex items-center justify-center px-1">
                {items.length > 9 ? '9+' : items.length}
              </span>
            )}
          </button>

          {open && (
            <div className="absolute right-0 mt-2 w-80 bg-black/90 backdrop-blur-xl border border-white/10 rounded-lg shadow-2xl z-50 overflow-hidden">
              <div className="px-4 py-2 border-b border-white/10 text-xs font-medium text-white/60">
                Notifications
              </div>
              {!items.length ? (
                <div className="px-4 py-6 text-center text-xs text-white/60">You're all caught up.</div>
              ) : (
                <div className="max-h-96 overflow-y-auto">
                  {items.map((n) => (
                    <button
                      key={n.id}
                      onClick={() => openNotification(n)}
                      className="w-full text-left px-4 py-3 border-b border-white/10 hover:bg-white/5 transition-colors"
                    >
                      <p className="text-sm text-horus-ivory">{n.title}</p>
                      {n.body && <p className="text-xs text-white/60 mt-0.5">{n.body}</p>}
                      <p className="text-[10px] text-white/40 mt-1">
                        {new Date(n.created_at).toLocaleString()}
                      </p>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        <span className="text-xs text-white/60">{user?.email}</span>
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
