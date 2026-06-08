import { useState } from 'react'
import { api, friendlyErrorMessage } from '../../lib/api'
import type { Asset } from '../../hooks/useAssets'

interface Props {
  initialData?: Asset
  onCreated: () => void
  onCancel: () => void
}

export function AssetForm({ initialData, onCreated, onCancel }: Props) {
  const [form, setForm] = useState({
    name: initialData?.name || '',
    host: initialData?.host || '',
    port: initialData?.port || '',
    type: initialData?.type || 'web',
    is_internal: initialData?.is_internal || false,
    tags: initialData?.tags?.join(', ') || '',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const payload = {
        name: form.name,
        host: form.host,
        port: form.port ? Number(form.port) : null,
        type: form.type,
        is_internal: form.is_internal,
        tags: form.tags ? form.tags.split(',').map((t) => t.trim()) : [],
      }
      
      if (initialData) {
        await api.patch(`/assets/${initialData.id}`, payload)
      } else {
        await api.post('/assets', payload)
      }
      onCreated()
    } catch (e: unknown) {
      setError(friendlyErrorMessage(e, initialData ? 'Failed to update asset' : 'Failed to create asset'))
    } finally {
      setLoading(false)
    }
  }

  const field = 'bg-bg border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-accent w-full'

  return (
    <form onSubmit={submit} className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-muted mb-1 block">Name *</label>
          <input className={field} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
        </div>
        <div>
          <label className="text-xs text-muted mb-1 block">Host / URL *</label>
          <input className={field} value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="example.com" required />
        </div>
        <div>
          <label className="text-xs text-muted mb-1 block">Port</label>
          <input className={field} type="number" value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value })} placeholder="443" />
        </div>
        <div>
          <label className="text-xs text-muted mb-1 block">Type</label>
          <select className={field} value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
            {['web', 'ip', 'api', 'domain'].map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
      </div>

      <div>
        <label className="text-xs text-muted mb-1 block">Tags (comma-separated)</label>
        <input className={field} value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="production, critical, external" />
      </div>

      <label className="flex items-center gap-2 text-sm text-white cursor-pointer">
        <input type="checkbox" checked={form.is_internal} onChange={(e) => setForm({ ...form, is_internal: e.target.checked })} />
        Internal asset
      </label>

      {error && <p className="text-xs text-severity-critical">{error}</p>}

      <div className="flex justify-end gap-3 pt-2">
        <button type="button" onClick={onCancel} className="px-4 py-2 text-sm text-muted hover:text-white transition-colors">Cancel</button>
        <button type="submit" disabled={loading} className="px-4 py-2 text-sm bg-accent text-bg rounded hover:bg-accent/90 transition-colors disabled:opacity-50">
          {loading ? 'Saving…' : (initialData ? 'Save Changes' : 'Create Asset')}
        </button>
      </div>
    </form>
  )
}
