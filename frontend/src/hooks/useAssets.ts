import { useEffect, useState } from 'react'
import { api, friendlyErrorMessage } from '../lib/api'

export interface Asset {
  id: string
  name: string
  host: string
  port: number | null
  type: string
  is_internal: boolean
  is_active: boolean
  tags: string[]
  created_at: string
}

export function useAssets() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refresh = async () => {
    try {
      setLoading(true)
      const data = await api.get<Asset[]>('/assets')
      setAssets(data)
    } catch (e: unknown) {
      setError(friendlyErrorMessage(e, 'Failed to load assets'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { refresh() }, [])

  return { assets, loading, error, refresh }
}
