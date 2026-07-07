import { createClient } from '@supabase/supabase-js'

const url = import.meta.env.VITE_SUPABASE_URL as string
const key = import.meta.env.VITE_SUPABASE_ANON_KEY as string

export const supabase = createClient(url, key, {
  auth: {
    // Persist the session in storage and keep the access token fresh in the
    // background so a backgrounded tab doesn't come back with a stale token.
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
})
