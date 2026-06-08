import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import type { User } from '@supabase/supabase-js'
import { supabase } from '../lib/supabase'

export type Role = 'admin' | 'analyst' | 'viewer'

const HIERARCHY: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 }

interface UserCtx {
  user: User | null
  role: Role | null
  orgId: string | null
  hasProfile: boolean
  mustChangePassword: boolean
  loading: boolean
  can: (minimum: Role) => boolean
  refreshProfile: () => Promise<void>
  signOut: () => void
}

const UserContext = createContext<UserCtx>({
  user: null, role: null, orgId: null, hasProfile: false, mustChangePassword: false, loading: true,
  can: () => false, refreshProfile: async () => {}, signOut: () => {},
})

export function UserProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [role, setRole] = useState<Role | null>(null)
  const [orgId, setOrgId] = useState<string | null>(null)
  const [hasProfile, setHasProfile] = useState(false)
  const [mustChangePassword, setMustChangePassword] = useState(false)
  const [loading, setLoading] = useState(true)

  const loadProfile = async (userId: string) => {
    const { data } = await supabase
      .from('profiles')
      .select('role, org_id, must_change_password')
      .eq('id', userId)
      .maybeSingle()
    setHasProfile(Boolean(data))
    if (data) {
      setRole(data.role as Role)
      setOrgId(data.org_id)
      setMustChangePassword(Boolean(data.must_change_password))
    } else {
      setRole(null)
      setOrgId(null)
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
      else { setRole(null); setOrgId(null); setHasProfile(false); setMustChangePassword(false) }
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
      value={{ user, role, orgId, hasProfile, mustChangePassword, loading, can, refreshProfile, signOut }}
    >
      {children}
    </UserContext.Provider>
  )
}

export const useUser = () => useContext(UserContext)
