import { useEffect, useState } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import { Swords, LayoutDashboard, Server, Search, AlertTriangle, AlertCircle, Lock, Settings, Users, ScrollText, Brain, Bell, Clock, Radar, Eye, Activity, Mail, ShieldAlert, Radio, Cloud, X, ChevronDown, Check, PanelLeftClose, PanelLeftOpen, User } from 'lucide-react'
import { cn } from '../../lib/utils'
import { useRole, type Role } from '../../hooks/useRole'
import { useUser } from '../../contexts/UserContext'
import { api } from '../../lib/api'

interface OrgOption { org_id: string; name: string | null; role: string; icon: string | null; active: boolean }

type NavItem = { to: string; icon: React.ElementType; label: string; minRole?: Role }

const groups: { label: string; items: NavItem[] }[] = [
  {
    label: 'Overview',
    items: [
      { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
      { to: '/analytics', icon: Brain, label: 'Analytics' },
    ],
  },
  {
    label: 'Attack surface',
    items: [
      { to: '/assets', icon: Server, label: 'Assets' },
      { to: '/discovery', icon: Radar, label: 'Discovery' },
      { to: '/watchtower', icon: Eye, label: 'Watchtower' },
      { to: '/iris', icon: Radio, label: 'Iris' },
      { to: '/cloud', icon: Cloud, label: 'Cloud Security', minRole: 'admin' },
    ],
  },
  {
    label: 'Operations',
    items: [
      { to: '/scans', icon: Search, label: 'Scans' },
      { to: '/schedules', icon: Clock, label: 'Schedules' },
      { to: '/jobs', icon: Activity, label: 'Job history' },
    ],
  },
  {
    label: 'Threats',
    items: [
      { to: '/findings', icon: AlertTriangle, label: 'Findings' },
      { to: '/incidents', icon: AlertCircle, label: 'Incidents' },
      { to: '/adversarial', icon: Swords, label: 'Red / Blue' },
      { to: '/auth-phishing', icon: Mail, label: 'AuthPhishing', minRole: 'admin' },
      { to: '/credential-exposure', icon: ShieldAlert, label: 'Credential Exposure', minRole: 'admin' },
    ],
  },
  {
    label: 'Administration',
    items: [
      { to: '/team', icon: Users, label: 'Team' },
      { to: '/permissions', icon: Lock, label: 'Permissions' },
      { to: '/integrations', icon: Bell, label: 'Integrations', minRole: 'admin' },
      { to: '/audit', icon: ScrollText, label: 'Audit log', minRole: 'admin' },
      { to: '/settings', icon: Settings, label: 'Settings' },
    ],
  },
]

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { can } = useRole()
  const { orgName, orgIcon, user, fullName } = useUser()
  const location = useLocation()
  const navigate = useNavigate()

  const displayName = fullName || user?.email || 'Account'

  const [switcherOpen, setSwitcherOpen] = useState(false)
  const [orgs, setOrgs] = useState<OrgOption[]>([])
  const [switching, setSwitching] = useState(false)

  // Desktop-only collapse to an icon rail. Persisted so it survives reloads.
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('sidebar-collapsed') === '1')
  const toggleCollapsed = () =>
    setCollapsed((c) => {
      localStorage.setItem('sidebar-collapsed', c ? '0' : '1')
      return !c
    })

  const toggleSwitcher = async () => {
    const next = !switcherOpen
    setSwitcherOpen(next)
    if (next) {
      try {
        setOrgs(await api.get<OrgOption[]>('/orgs'))
      } catch {
        setOrgs([])
      }
    }
  }

  const switchOrg = async (orgId: string) => {
    if (switching) return
    setSwitching(true)
    try {
      await api.post(`/orgs/${orgId}/switch`)
      // Switching org changes the entire dataset (RLS re-scopes to the new org). A full
      // reload is the simplest way to guarantee no stale cross-org data lingers in caches.
      window.location.reload()
    } catch {
      setSwitching(false)
      setSwitcherOpen(false)
    }
  }

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
          'transition-[transform,width] duration-300 ease-out',
          // From md up: static column, always visible. Collapsed shrinks to an icon rail.
          'md:relative md:z-10 md:translate-x-0',
          collapsed ? 'md:w-16' : 'md:w-60',
          open ? 'translate-x-0' : '-translate-x-full',
        )}
      >
        <div className="relative border-b border-white/10">
          <div className="flex items-center gap-2 px-3 py-4">
            <button
              onClick={toggleSwitcher}
              aria-haspopup="menu"
              aria-expanded={switcherOpen}
              aria-label="Switch organization"
              className={cn(
                'flex items-center gap-3 flex-1 min-w-0 rounded-md px-2 py-1.5 hover:bg-white/10 transition-colors',
                collapsed && 'md:justify-center md:px-0',
              )}
            >
              <div className="glass specular rounded-lg w-8 h-8 flex items-center justify-center shrink-0 text-horus-gold">
                {orgIcon ? <span className="text-base leading-none">{orgIcon}</span> : <Eye className="w-4 h-4" />}
              </div>
              <span className={cn('font-semibold text-horus-ivory tracking-tight truncate', collapsed && 'md:hidden')}>
                Horus{orgName ? ` × ${orgName}` : ''}
              </span>
              <ChevronDown className={cn('w-4 h-4 text-white/50 shrink-0 transition-transform', switcherOpen && 'rotate-180', collapsed && 'md:hidden')} />
            </button>
            <button
              onClick={onClose}
              aria-label="Close navigation"
              className="-mr-1 p-1 text-white/60 hover:text-white transition-colors md:hidden"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {switcherOpen && (
            <>
              <div className="fixed inset-0 z-40" aria-hidden="true" onClick={() => setSwitcherOpen(false)} />
              <div
                role="menu"
                className={cn(
                  'absolute top-full z-50 -mt-1 rounded-md border border-white/10 bg-[#141a2b] shadow-2xl py-1 max-h-72 overflow-y-auto',
                  collapsed ? 'left-2 w-56' : 'left-3 right-3',
                )}
              >
                {orgs.length === 0 ? (
                  <p className="px-3 py-2 text-xs text-white/50">No organizations</p>
                ) : (
                  orgs.map((o) => (
                    <button
                      key={o.org_id}
                      role="menuitem"
                      disabled={switching}
                      onClick={() => (o.active ? setSwitcherOpen(false) : switchOrg(o.org_id))}
                      className="flex items-center gap-2 w-full px-3 py-2 text-sm text-left text-white/80 hover:bg-white/10 transition-colors disabled:opacity-50"
                    >
                      <span className="w-5 text-center shrink-0">{o.icon || '🏢'}</span>
                      <span className="truncate flex-1">{o.name || 'Untitled org'}</span>
                      {o.active && <Check className="w-4 h-4 text-horus-gold shrink-0" />}
                    </button>
                  ))
                )}
              </div>
            </>
          )}
        </div>
        <nav className="flex-1 px-3 py-4 space-y-5 overflow-y-auto">
          {groups.map((group) => {
            const items = group.items.filter((l) => !l.minRole || can(l.minRole))
            if (items.length === 0) return null
            return (
              <div key={group.label}>
                <p className={cn('px-3 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-white/35', collapsed && 'md:hidden')}>
                  {group.label}
                </p>
                <div className="space-y-0.5">
                  {items.map(({ to, icon: Icon, label }) => (
                    <NavLink
                      key={to}
                      to={to}
                      aria-label={label}
                      title={collapsed ? label : undefined}
                      className={({ isActive }) =>
                        cn(
                          'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors',
                          collapsed && 'md:justify-center md:px-0',
                          isActive
                            ? 'bg-horus-lapis text-white'
                            : 'text-white/60 hover:text-white hover:bg-white/10',
                        )
                      }
                    >
                      <Icon className="w-4 h-4 shrink-0" />
                      <span className={cn(collapsed && 'md:hidden')}>{label}</span>
                    </NavLink>
                  ))}
                </div>
              </div>
            )
          })}
        </nav>
        <div className="border-t border-white/10 p-3 space-y-1">
          <button
            onClick={() => { navigate('/account'); onClose() }}
            aria-label="Account"
            title={collapsed ? displayName : undefined}
            className={cn(
              'flex items-center gap-3 w-full px-3 py-2 rounded-md text-sm transition-colors',
              collapsed && 'md:justify-center md:px-0',
              location.pathname === '/account'
                ? 'bg-horus-lapis text-white'
                : 'text-white/60 hover:text-white hover:bg-white/10',
            )}
          >
            <User className="w-4 h-4 shrink-0" />
            <span className={cn('truncate', collapsed && 'md:hidden')}>{displayName}</span>
          </button>
          <button
            onClick={toggleCollapsed}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className={cn(
              'hidden md:flex items-center gap-3 w-full px-3 py-2 rounded-md text-sm text-white/60 hover:text-white hover:bg-white/10 transition-colors',
              collapsed && 'md:justify-center md:px-0',
            )}
          >
            {collapsed ? <PanelLeftOpen className="w-4 h-4 shrink-0" /> : <PanelLeftClose className="w-4 h-4 shrink-0" />}
            <span className={cn(collapsed && 'md:hidden')}>Collapse</span>
          </button>
        </div>
      </aside>
    </>
  )
}
