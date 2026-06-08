import { useEffect } from 'react'
import { supabase } from '../lib/supabase'

type RealtimeCallback = (payload: unknown) => void

export function useRealtime(
  table: string,
  orgId: string | undefined,
  onInsert?: RealtimeCallback,
  onUpdate?: RealtimeCallback,
) {
  useEffect(() => {
    if (!orgId) return

    const channel = supabase
      .channel(`${table}:${orgId}`)
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table,
          filter: `org_id=eq.${orgId}`,
        },
        (payload) => onInsert?.(payload),
      )
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table,
          filter: `org_id=eq.${orgId}`,
        },
        (payload) => onUpdate?.(payload),
      )
      .subscribe()

    return () => {
      supabase.removeChannel(channel)
    }
  }, [table, orgId])
}
