import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Server, Activity, Edit2 } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import type { Asset } from '../hooks/useAssets'
import { AssetForm } from '../components/assets/AssetForm'

interface ScanRow {
  id: string
  status: string
  created_at: string
}

export default function AssetDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [asset, setAsset] = useState<Asset | null>(null)
  const [scans, setScans] = useState<ScanRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [isEditing, setIsEditing] = useState(false)

  const fetchAsset = () => {
    if (!id) return
    setLoading(true)
    Promise.all([
      api.get<Asset>(`/assets/${id}`),
      api.get<ScanRow[]>('/scans')
    ])
      .then(([aData, sData]) => {
        setAsset(aData)
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

      <div className="bg-surface border border-border rounded-lg p-6">
        <h2 className="text-lg font-medium mb-4">Related Scans</h2>
        <p className="text-sm text-muted">
          (A real implementation would list the scans for this asset here, fetching from /assets/{id}/scans)
        </p>
      </div>
    </div>
  )
}
