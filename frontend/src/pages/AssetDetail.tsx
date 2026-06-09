import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Server, Activity, Edit2 } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { api, friendlyErrorMessage } from '../lib/api'
import type { Asset } from '../hooks/useAssets'
import { AssetForm } from '../components/assets/AssetForm'
import { cn } from '../lib/utils'

interface AssetScan {
  id: string
  status: string
  created_at: string
  started_at: string | null
  completed_at: string | null
  triggered_by_label: string
}

interface FindingsSummary {
  open_by_severity: Record<string, number>
  total: number
}

interface InventoryItem {
  product: string
  version: string | null
  port: string
  service_name: string | null
  last_seen_at: string
}

const STATUS_COLOR: Record<string, string> = {
  completed: 'text-mode-auto bg-mode-auto/10 border-mode-auto/30',
  running: 'text-accent bg-accent/10 border-accent/30',
  failed: 'text-severity-critical bg-severity-critical/10 border-severity-critical/30',
  canceled: 'text-muted bg-white/[0.03] border-border',
  pending: 'text-muted bg-surface border-border',
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-severity-critical bg-severity-critical/10 border-severity-critical/30',
  high: 'text-severity-high bg-severity-high/10 border-severity-high/30',
  medium: 'text-severity-medium bg-severity-medium/10 border-severity-medium/30',
  low: 'text-severity-low bg-severity-low/10 border-severity-low/30',
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']

export default function AssetDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [asset, setAsset] = useState<Asset | null>(null)
  const [scans, setScans] = useState<AssetScan[]>([])
  const [findingsSummary, setFindingsSummary] = useState<FindingsSummary | null>(null)
  const [inventory, setInventory] = useState<InventoryItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isEditing, setIsEditing] = useState(false)

  const fetchAsset = () => {
    if (!id) return
    setLoading(true)
    Promise.all([
      api.get<Asset>(`/assets/${id}`),
      api.get<AssetScan[]>(`/assets/${id}/scans`),
      api.get<FindingsSummary>(`/assets/${id}/findings/summary`),
      api.get<InventoryItem[]>(`/assets/${id}/inventory`),
    ])
      .then(([aData, sData, fData, iData]) => {
        setAsset(aData)
        setScans(sData)
        setFindingsSummary(fData)
        setInventory(iData)
      })
      .catch((e) => setError(friendlyErrorMessage(e, 'Failed to load asset details')))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchAsset()
  }, [id])

  if (loading && !asset) return <div className="p-6 text-sm text-muted">Loading asset…</div>
  if (error || !asset) return (
    <div className="p-6">
      <div className="border border-severity-critical/40 bg-severity-critical/10 px-4 py-3 text-sm text-severity-critical">
        {error || 'Asset not found'}
      </div>
      <button onClick={() => navigate('/assets')} className="mt-4 text-sm text-accent hover:underline">
        &larr; Back to Assets
      </button>
    </div>
  )

  const openBySev = findingsSummary?.open_by_severity ?? {}
  const hasOpenFindings = Object.keys(openBySev).length > 0

  return (
    <div className="space-y-6">
      <div>
        <button onClick={() => navigate('/assets')} className="flex items-center gap-2 text-sm text-muted hover:text-white transition-colors mb-4">
          <ArrowLeft className="w-4 h-4" /> Back to Assets
        </button>
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-white flex items-center gap-2">
              <Server className="w-6 h-6 text-accent" />
              {asset.name}
            </h1>
            <p className="text-muted mt-1 font-mono text-sm">
              {asset.host}{asset.port ? `:${asset.port}` : ''}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsEditing(!isEditing)}
              className="flex items-center gap-2 px-3 py-1.5 text-sm bg-white/5 hover:bg-white/10 border border-white/10 rounded transition-colors"
            >
              <Edit2 className="w-4 h-4" /> Edit
            </button>
            <span className="text-xs bg-white/5 border border-white/10 px-2 py-1 rounded text-white/80 uppercase ml-2">
              {asset.type}
            </span>
            <span className={`text-xs px-2 py-1 rounded border ${asset.is_internal ? 'border-mode-auto/30 bg-mode-auto/10 text-mode-auto' : 'border-severity-medium/30 bg-severity-medium/10 text-severity-medium'}`}>
              {asset.is_internal ? 'Internal' : 'External'}
            </span>
          </div>
        </div>
      </div>

      {isEditing && (
        <div className="bg-surface border border-border rounded-lg p-6">
          <h2 className="text-sm font-medium mb-4">Edit Asset</h2>
          <AssetForm
            initialData={asset}
            onCreated={() => { setIsEditing(false); fetchAsset() }}
            onCancel={() => setIsEditing(false)}
          />
        </div>
      )}

      <div className="bg-surface border border-border rounded-lg p-6">
        <h2 className="text-lg font-medium mb-4 flex items-center gap-2">
          <Activity className="w-5 h-5 text-muted" />
          Asset Details
        </h2>
        <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-4 text-sm">
          <div>
            <dt className="text-muted mb-1">Created At</dt>
            <dd className="text-white">{new Date(asset.created_at).toLocaleString()}</dd>
          </div>
          <div>
            <dt className="text-muted mb-1">Status</dt>
            <dd className="text-white">{asset.is_active ? 'Active' : 'Inactive'}</dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-muted mb-1">Tags</dt>
            <dd className="flex flex-wrap gap-2 mt-1">
              {asset.tags && asset.tags.length > 0 ? (
                asset.tags.map(t => (
                  <span key={t} className="text-xs bg-accent/10 text-accent border border-accent/20 px-2 py-1 rounded">
                    {t}
                  </span>
                ))
              ) : (
                <span className="text-muted italic">No tags</span>
              )}
            </dd>
          </div>
        </dl>
      </div>

      {/* Open Findings */}
      <div className="bg-surface border border-border rounded-lg p-6">
        <h2 className="text-lg font-medium mb-4">Open Findings</h2>
        {hasOpenFindings ? (
          <div className="flex flex-wrap gap-3">
            {SEVERITY_ORDER.filter(sev => openBySev[sev] != null).map(sev => (
              <span
                key={sev}
                className={cn('text-sm px-3 py-1.5 rounded border font-medium capitalize', SEVERITY_COLOR[sev] ?? 'text-muted border-border')}
              >
                {sev}: {openBySev[sev]}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted">No open findings</p>
        )}
      </div>

      {/* Related Scans */}
      <div className="bg-surface border border-border rounded-lg p-6">
        <h2 className="text-lg font-medium mb-4">Related Scans</h2>
        {scans.length === 0 ? (
          <p className="text-sm text-muted">No scans yet</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-muted">
                  <th className="text-left py-3 px-4 font-medium">Status</th>
                  <th className="text-left py-3 px-4 font-medium">Triggered by</th>
                  <th className="text-left py-3 px-4 font-medium">Date</th>
                  <th className="text-left py-3 px-4 font-medium">Duration</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => {
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
                        <span className={cn('text-xs px-2 py-0.5 rounded border capitalize', STATUS_COLOR[scan.status] ?? STATUS_COLOR.pending)}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-muted text-xs">{scan.triggered_by_label || '—'}</td>
                      <td className="py-3 px-4 text-muted text-xs">
                        {formatDistanceToNow(new Date(scan.created_at))} ago
                      </td>
                      <td className="py-3 px-4 text-muted text-xs">{duration}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Detected Technologies */}
      <div className="bg-surface border border-border rounded-lg p-6">
        <h2 className="text-lg font-medium mb-4">Detected Technologies</h2>
        {inventory.length === 0 ? (
          <p className="text-sm text-muted">No inventory data yet — run a scan</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-muted">
                  <th className="text-left py-3 px-4 font-medium">Product</th>
                  <th className="text-left py-3 px-4 font-medium">Version</th>
                  <th className="text-left py-3 px-4 font-medium">Port</th>
                  <th className="text-left py-3 px-4 font-medium">Service</th>
                </tr>
              </thead>
              <tbody>
                {inventory.map((item, idx) => (
                  <tr key={idx} className="border-b border-border">
                    <td className="py-3 px-4 text-white font-medium">{item.product}</td>
                    <td className="py-3 px-4 text-muted text-xs">{item.version ?? '—'}</td>
                    <td className="py-3 px-4 text-muted text-xs font-mono">{item.port}</td>
                    <td className="py-3 px-4 text-muted text-xs">{item.service_name ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
