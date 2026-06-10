import { NavLink } from 'react-router-dom'
import { Swords, LayoutDashboard, Server, Search, AlertTriangle, AlertCircle, Lock, Settings, Users, ScrollText, Brain, Bell, Clock, Radar, Eye, Activity, Mail, ShieldAlert } from 'lucide-react'
import { cn } from '../../lib/utils'
import { useRole, type Role } from '../../hooks/useRole'

const links: { to: string; icon: React.ElementType; label: string; minRole?: Role }[] = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/assets', icon: Server, label: 'Assets' },
  { to: '/discovery', icon: Radar, label: 'Discovery' },
  { to: '/watchtower', icon: Eye, label: 'Watchtower' },
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

export function Sidebar() {
  const { can } = useRole()
  return (
    <aside className="w-60 glass border-r-0 border-white/10 flex flex-col h-full z-10 shadow-2xl">
      <div className="flex items-center gap-3 px-5 py-4 border-b border-white/10">
        <div className="glass specular rounded-lg w-8 h-8 flex items-center justify-center">
          <Eye className="w-4 h-4 text-horus-gold" />
        </div>
        <span className="font-semibold text-horus-ivory tracking-tight">Horus</span>
      </div>
      <nav className="flex-1 px-3 py-4 space-y-1">
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
  )
}
