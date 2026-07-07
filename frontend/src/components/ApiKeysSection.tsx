import { useEffect, useState } from 'react'
import { Copy, Trash2, Plus } from 'lucide-react'
import { api } from '../lib/api'
import { Select } from './ui/Select'
import { useConfirm, useAlert } from './ui/ConfirmProvider'
import { Modal } from './Modal'

interface ApiKey {
  id: string
  name: string
  key_prefix: string
  role: string
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
}

interface ApiKeySecret {
  secret: string
  key_prefix: string
  [key: string]: string | null | undefined
}

export function ApiKeysSection() {
  const confirm = useConfirm()
  const alert = useAlert()
  const [keys, setKeys] = useState<ApiKey[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [name, setName] = useState('')
  const [role, setRole] = useState('analyst')
  const [creating, setCreating] = useState(false)
  const [secret, setSecret] = useState<ApiKeySecret | null>(null)
  const [copied, setCopied] = useState(false)

  const loadKeys = () => {
    setLoading(true)
    api
      .get<ApiKey[]>('/api-keys')
      .then(setKeys)
      .catch(() => setKeys([]))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadKeys()
  }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return

    setCreating(true)
    try {
      const result = await api.post<ApiKeySecret>('/api-keys', { name, role })
      setSecret(result)
      setName('')
      setShowForm(false)
      loadKeys()
    } finally {
      setCreating(false)
    }
  }

  const handleCopy = () => {
    if (secret?.secret) {
      navigator.clipboard.writeText(secret.secret)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const handleRevoke = async (id: string) => {
    if (!(await confirm({ message: 'Revoke this API key?', danger: true, confirmLabel: 'Revoke' }))) return
    try {
      await api.delete(`/api-keys/${id}`)
      loadKeys()
    } catch {
      await alert('Failed to revoke key')
    }
  }

  if (loading) return <div className="text-muted">Loading API keys...</div>

  return (
    <section className="bg-surface border border-border rounded-lg p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-white">API keys</h2>
        {!showForm && (
          <button
            onClick={() => setShowForm(true)}
            className="text-xs bg-accent text-bg px-3 py-1.5 rounded hover:bg-accent/90 flex items-center gap-1.5 transition"
          >
            <Plus className="w-3.5 h-3.5" />
            Create
          </button>
        )}
      </div>

      {secret && (
        <div className="bg-bg border border-severity-medium/30 rounded-lg p-4 space-y-3">
          <p className="text-xs text-severity-medium font-semibold">Save your API key now</p>
          <div className="bg-bg-dark rounded p-2.5 font-mono text-[11px] text-success break-all flex items-start gap-2">
            <span className="text-muted flex-shrink-0 mt-0.5">{secret.key_prefix}</span>
            <span className="flex-shrink-0">•••</span>
            <span className="flex-1">visible only once</span>
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleCopy}
              className="text-xs bg-accent/20 text-accent hover:bg-accent/30 px-3 py-1.5 rounded transition flex items-center gap-1.5"
            >
              <Copy className="w-3.5 h-3.5" />
              {copied ? 'Copied!' : 'Copy'}
            </button>
            <button
              onClick={() => setSecret(null)}
              className="text-xs bg-border text-muted hover:bg-border/80 px-3 py-1.5 rounded transition"
            >
              Done
            </button>
          </div>
        </div>
      )}

      <Modal
        open={showForm && !secret}
        onClose={() => {
          setShowForm(false)
          setName('')
        }}
        title="New API key"
        className="max-w-md"
      >
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="text-xs text-muted uppercase tracking-wide block mb-1.5">
              Key name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., SIEM export"
              className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-white placeholder:text-muted/60 focus:outline-none focus:border-accent transition"
              disabled={creating}
            />
          </div>
          <div>
            <label className="text-xs text-muted uppercase tracking-wide block mb-1.5">
              Role
            </label>
            <Select
              className="w-full"
              value={role}
              onValueChange={(v) => setRole(v)}
              disabled={creating}
              options={[
                { value: 'analyst', label: 'Analyst (read-only)' },
                { value: 'admin', label: 'Admin' },
              ]}
            />
          </div>
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={creating}
              className="text-xs bg-accent text-bg px-4 py-2 rounded hover:bg-accent/90 disabled:opacity-50 transition"
            >
              {creating ? 'Creating...' : 'Create'}
            </button>
            <button
              type="button"
              onClick={() => {
                setShowForm(false)
                setName('')
              }}
              className="text-xs bg-border text-muted hover:bg-border/80 px-4 py-2 rounded transition"
            >
              Cancel
            </button>
          </div>
        </form>
      </Modal>

      {keys.length === 0 && !showForm && !secret && (
        <p className="text-xs text-muted">No API keys yet. Create one to get started.</p>
      )}

      {keys.length > 0 && (
        <div className="space-y-2 border-t border-border pt-4">
          {keys.map((key) => (
            <div key={key.id} className="flex items-center justify-between bg-bg rounded p-3">
              <div className="min-w-0">
                <p className="text-sm font-mono text-accent">{key.key_prefix}</p>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-xs text-muted">{key.name}</span>
                  <span className="text-[10px] bg-border/50 text-muted-foreground px-1.5 py-0.5 rounded">
                    {key.role}
                  </span>
                  {key.last_used_at && (
                    <span className="text-[10px] text-muted">
                      Used {new Date(key.last_used_at).toLocaleDateString()}
                    </span>
                  )}
                </div>
              </div>
              <button
                onClick={() => handleRevoke(key.id)}
                className="p-1.5 hover:bg-severity-high/20 rounded transition text-severity-high"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
