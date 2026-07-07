import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import type { User } from '@supabase/supabase-js'
import { supabase } from '../lib/supabase'

export type Role = 'admin' | 'analyst' | 'viewer'

const HIERARCHY: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 }

interface UserCtx {
  user: User | null
  fullName: string | null
  role: Role | null
  orgId: string | null
  orgName: string | null
  orgIcon: string | null
  hasProfile: boolean
  mustChangePassword: boolean
  loading: boolean
  can: (minimum: Role) => boolean
  refreshProfile: () => Promise<void>
  signOut: () => void
}

const UserContext = createContext<UserCtx>({
  user: null, fullName: null, role: null, orgId: null, orgName: null, orgIcon: null,
  hasProfile: false, mustChangePassword: false, loading: true,
  can: () => false, refreshProfile: async () => {}, signOut: () => {},
})

export function UserProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [fullName, setFullName] = useState<string | null>(null)
  const [role, setRole] = useState<Role | null>(null)
  const [orgId, setOrgId] = useState<string | null>(null)
  const [orgName, setOrgName] = useState<string | null>(null)
  const [orgIcon, setOrgIcon] = useState<string | null>(null)
  const [hasProfile, setHasProfile] = useState(false)
  const [mustChangePassword, setMustChangePassword] = useState(false)
  const [loading, setLoading] = useState(true)

  const loadProfile = async (userId: string) => {
    // organizations() is the active org (RLS own_org lets you read the org you're in).
    const { data } = await supabase
      .from('profiles')
      .select('full_name, role, org_id, must_change_password, organizations(name, settings)')
      .eq('id', userId)
      .maybeSingle()
    setHasProfile(Boolean(data))
    if (data) {
      const org = (data.organizations ?? null) as { name?: string; settings?: { icon?: string } } | null
      setFullName((data.full_name as string | null) ?? null)
      setRole(data.role as Role)
      setOrgId(data.org_id)
      setOrgName(org?.name ?? null)
      setOrgIcon(org?.settings?.icon ?? null)
      setMustChangePassword(Boolean(data.must_change_password))
    } else {
      setFullName(null)
      setRole(null)
      setOrgId(null)
      setOrgName(null)
      setOrgIcon(null)
      setMustChangePassword(false)
    }
  }

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      const u = data.session?.user ?? null
      setUser(u)
      if (u) loadProfile(u.id).finally(() => setLoading(false))
      else setLoading(false)
    })

    const { data: listener } = supabase.auth.onAuthStateChange((_event, session) => {
      const u = session?.user ?? null
      setUser(u)
      if (u) loadProfile(u.id)
      else { setFullName(null); setRole(null); setOrgId(null); setOrgName(null); setOrgIcon(null); setHasProfile(false); setMustChangePassword(false) }
    })
    return () => listener.subscription.unsubscribe()
  }, [])

  const can = (minimum: Role) =>
    role !== null && HIERARCHY[role] >= HIERARCHY[minimum]

  const refreshProfile = async () => {
    if (user) await loadProfile(user.id)
  }

  const signOut = () => supabase.auth.signOut()

  return (
    <UserContext.Provider
      value={{ user, fullName, role, orgId, orgName, orgIcon, hasProfile, mustChangePassword, loading, can, refreshProfile, signOut }}
    >
      {children}
    </UserContext.Provider>
  )
}

export const useUser = () => useContext(UserContext)
