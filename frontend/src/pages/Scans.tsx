import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { formatDistanceToNow } from 'date-fns'
import { XCircle, Radar } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { useAssets } from '../hooks/useAssets'
import { cn } from '../lib/utils'

interface Scan {
  id: string
  status: string
  triggered_by: string
  triggered_by_label: string
  created_at: string
  started_at: string | null
  completed_at: string | null
  error_message: string | null
  assets: { name: string; host: string }
}

const STATUS_COLOR: Record<string, string> = {
  completed: 'text-mode-auto bg-mode-auto/10 border-mode-auto/30',
  running: 'text-accent bg-accent/10 border-accent/30',
  failed: 'text-severity-critical bg-severity-critical/10 border-severity-critical/30',
  canceled: 'text-muted bg-white/[0.03] border-border',
  pending: 'text-muted bg-surface border-border',
}

export default function Scans() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [canceling, setCanceling] = useState<string | null>(null)
  const [scanningAll, setScanningAll] = useState(false)
  const { assets } = useAssets()
  const navigate = useNavigate()

  const activeAssetCount = assets.filter((a) => a.is_active).length

  const load = async () => {
    try {
      const data = await api.get<Scan[]>('/scans')
      setScans(data)
      setError(null)
    } catch (e: unknown) {
      setError(friendlyErrorMessage(e, 'Failed to load scans'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const activeCount = scans.filter((scan) => scan.status === 'pending' || scan.status === 'running').length

  const cancelScan = async (scanId: string) => {
    setCanceling(scanId)
    try {
      await api.post(`/scans/${scanId}/cancel`)
      await load()
    } catch (e: unknown) {
      setError(friendlyErrorMessage(e, 'Failed to cancel scan'))
    } finally {
      setCanceling(null)
    }
  }

  const scanAll = async () => {
    if (!confirm(`Queue a scan for all ${activeAssetCount} active asset${activeAssetCount === 1 ? '' : 's'}?`)) return
    setScanningAll(true)
    try {
      await api.post('/scans/scan-all')
      await load()
    } catch (e: unknown) {
      setError(friendlyErrorMessage(e, 'Failed to start scans'))
    } finally {
      setScanningAll(false)
    }
  }

  const cancelActive = async () => {
    if (!confirm(`Cancel all ${activeCount} active scan${activeCount === 1 ? '' : 's'}?`)) return
    setCanceling('active')
    try {
      await api.post('/scans/cancel-active')
      await load()
    } catch (e: unknown) {
      setError(friendlyErrorMessage(e, 'Failed to cancel active scans'))
    } finally {
      setCanceling(null)
    }
  }

  if (loading) return <p className="text-muted text-sm">Loading…</p>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Scans</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={scanAll}
            disabled={activeAssetCount === 0 || scanningAll || canceling !== null}
            className="flex items-center gap-2 bg-accent/10 text-accent px-3 py-2 text-xs rounded-md hover:bg-accent/20 disabled:cursor-not-allowed disabled:opacity-40 transition-colors"
            title="Queue a scan for every active asset"
          >
            <Radar className="h-4 w-4" />
            {scanningAll ? 'Starting…' : `Scan All${activeAssetCount ? ` (${activeAssetCount})` : ''}`}
          </button>
          <button
            onClick={cancelActive}
            disabled={activeCount === 0 || canceling !== null}
            className="flex items-center gap-2 border border-border px-3 py-2 text-xs text-muted hover:text-severity-critical disabled:cursor-not-allowed disabled:opacity-40"
          >
            <XCircle className="h-4 w-4" />
            Cancel Active
          </button>
        </div>
      </div>
      {error && (
        <div className="border border-severity-critical/40 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical">
          {error}
        </div>
      )}
      <div className="bg-surface border border-border rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-xs text-muted">
              <th className="text-left py-3 px-4 font-medium">Asset</th>
              <th className="text-left py-3 px-4 font-medium">Status</th>
              <th className="text-left py-3 px-4 font-medium">Triggered by</th>
              <th className="text-left py-3 px-4 font-medium">Started</th>
              <th className="text-left py-3 px-4 font-medium">Duration</th>
              <th className="py-3 px-4" />
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => {
              const displayStatus = scan.status === 'failed' && scan.error_message === 'Canceled by user'
                ? 'canceled'
                : scan.status
              const duration =
                scan.started_at && scan.completed_at
                  ? `${Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)}s`
                  : '—'
              return (
                <tr
                  key={scan.id}
                  className="border-b border-border hover:bg-white/[0.02] cursor-pointer transition-colors"
                  onClick={() => navigate(`/scans/${scan.id}`)}
                >
                  <td className="py-3 px-4">
                    <p className="font-medium text-white">{scan.assets?.name}</p>
                    <p className="text-xs text-muted">{scan.assets?.host}</p>
                  </td>
                  <td className="py-3 px-4">
                    <span className={cn('text-xs px-2 py-0.5 rounded border capitalize', STATUS_COLOR[displayStatus])}>
                      {displayStatus}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-muted text-xs">{scan.triggered_by_label}</td>
                  <td className="py-3 px-4 text-muted text-xs">
                    {scan.started_at ? formatDistanceToNow(new Date(scan.started_at)) + ' ago' : '—'}
                  </td>
                  <td className="py-3 px-4 text-muted text-xs">{duration}</td>
                  <td className="py-3 px-4">
                    {(scan.status === 'pending' || scan.status === 'running') && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          cancelScan(scan.id)
                        }}
                        disabled={canceling !== null}
                        className="flex items-center gap-1 text-xs text-muted hover:text-severity-critical disabled:cursor-wait disabled:opacity-40"
                        title="Cancel scan"
                      >
                        <XCircle className="h-3.5 w-3.5" />
                        Cancel
                      </button>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
