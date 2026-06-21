import { useEffect } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { Swords, LayoutDashboard, Server, Search, AlertTriangle, AlertCircle, Lock, Settings, Users, ScrollText, Brain, Bell, Clock, Radar, Eye, Activity, Mail, ShieldAlert, Radio, Cloud, X } from 'lucide-react'
import { cn } from '../../lib/utils'
import { useRole, type Role } from '../../hooks/useRole'

const links: { to: string; icon: React.ElementType; label: string; minRole?: Role }[] = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/assets', icon: Server, label: 'Assets' },
  { to: '/discovery', icon: Radar, label: 'Discovery' },
  { to: '/watchtower', icon: Eye, label: 'Watchtower' },
  { to: '/iris', icon: Radio, label: 'Iris' },
  { to: '/cloud', icon: Cloud, label: 'Cloud Security', minRole: 'admin' },
  { to: '/scans', icon: Search, label: 'Scans' },
  { to: '/schedules', icon: Clock, label: 'Schedules' },
  { to: '/jobs', icon: Activity, label: 'Job history' },
  { to: '/findings', icon: AlertTriangle, label: 'Findings' },
  { to: '/incidents', icon: AlertCircle, label: 'Incidents' },
  { to: '/adversarial', icon: Swords, label: 'Red / Blue' },
  { to: '/auth-phishing', icon: Mail, label: 'AuthPhishing', minRole: 'admin' },
  { to: '/credential-exposure', icon: ShieldAlert, label: 'Credential Exposure', minRole: 'admin' },
  { to: '/permissions', icon: Lock, label: 'Permissions' },
  { to: '/team', icon: Users, label: 'Team' },
  { to: '/audit', icon: ScrollText, label: 'Audit log', minRole: 'admin' },
  { to: '/integrations', icon: Bell, label: 'Integrations', minRole: 'admin' },
  { to: '/settings', icon: Settings, label: 'Settings' },
  { to: '/analytics', icon: Brain, label: 'Analytics' },
]

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { can } = useRole()
  const location = useLocation()

  // Close the mobile drawer whenever the route changes (covers nav clicks and
  // navigations triggered elsewhere, e.g. the command palette).
  useEffect(() => {
    onClose()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname])

  // Escape closes the drawer while it's open.
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  return (
    <>
      {/* Backdrop — mobile only, fades with the drawer. */}
      <div
        onClick={onClose}
        aria-hidden="true"
        className={cn(
          'fixed inset-0 z-30 bg-black/60 backdrop-blur-sm transition-opacity duration-300 md:hidden',
          open ? 'opacity-100' : 'pointer-events-none opacity-0',
        )}
      />
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-40 w-60 glass border-r-0 border-white/10 flex flex-col shadow-2xl',
          'transition-transform duration-300 ease-out',
          // From md up: static column, always visible.
          'md:relative md:z-10 md:translate-x-0',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="flex items-center gap-3 px-5 py-4 border-b border-white/10">
          <div className="glass specular rounded-lg w-8 h-8 flex items-center justify-center">
            <Eye className="w-4 h-4 text-horus-gold" />
          </div>
          <span className="font-semibold text-horus-ivory tracking-tight">Horus</span>
          <button
            onClick={onClose}
            aria-label="Close navigation"
            className="ml-auto -mr-1 p-1 text-white/60 hover:text-white transition-colors md:hidden"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {links.filter((l) => !l.minRole || can(l.minRole)).map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors',
                  isActive
                    ? 'bg-horus-lapis text-white'
                    : 'text-white/60 hover:text-white hover:bg-white/10',
                )
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>
    </>
  )
}
