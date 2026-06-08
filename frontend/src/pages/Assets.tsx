import { useState } from 'react'
import { Plus } from 'lucide-react'
import { useAssets } from '../hooks/useAssets'
import { AssetList } from '../components/assets/AssetList'
import { AssetForm } from '../components/assets/AssetForm'

export default function Assets() {
  const { assets, loading, error, refresh } = useAssets()
  const [showForm, setShowForm] = useState(false)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Assets</h1>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-2 bg-accent text-bg text-sm px-4 py-2 rounded hover:bg-accent/90 transition-colors"
        >
          <Plus className="w-4 h-4" /> Add Asset
        </button>
      </div>

      {showForm && (
        <div className="bg-surface border border-border rounded-lg p-6">
          <h2 className="text-sm font-medium mb-4">New Asset</h2>
          <AssetForm onCreated={() => { setShowForm(false); refresh() }} onCancel={() => setShowForm(false)} />
        </div>
      )}

      {error && (
        <div className="border border-severity-critical/40 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical">
          {error}
        </div>
      )}

      {loading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : (
        <div className="bg-surface border border-border rounded-lg">
          <AssetList assets={assets} onRefresh={refresh} />
        </div>
      )}
    </div>
  )
}
