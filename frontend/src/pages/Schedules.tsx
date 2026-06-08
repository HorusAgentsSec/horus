import { useEffect, useState } from 'react'
import { formatDistanceToNow } from 'date-fns'
import { Clock, Plus, Trash2, X, CheckCircle, XCircle } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { useAssets } from '../hooks/useAssets'
import { cn } from '../lib/utils'

interface Schedule {
  id: string
  name: string
  asset_ids: string[]
  cron_expression: string
  tools: string[]
  enabled: boolean
  last_run: { status: string; started_at: string; detail?: Record<string, unknown> } | null
  next_run: string | null
}

const CRON_PRESETS: { label: string; value: string }[] = [
  { label: 'Daily at 02:00', value: '0 2 * * *' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
  { label: 'Weekly (Mon 03:00)', value: '0 3 * * 1' },
  { label: 'Custom…', value: 'custom' },
]
const ALL_TOOLS = ['nuclei', 'nmap'] as const

const input =
  'bg-bg border border-border text-sm text-white rounded px-3 py-1.5 w-full focus:outline-none focus:border-accent placeholder:text-muted/60'
const label = 'text-xs text-muted mb-1 block'

function cronLabel(cron: string): string {
  return CRON_PRESETS.find((p) => p.value === cron)?.label ?? cron
}

export default function Schedules() {
  const [items, setItems] = useState<Schedule[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)

  const load = () => {
    setLoading(true)
    api.get<Schedule[]>('/schedules').then(setItems).finally(() => setLoading(false))
  }
  useEffect(load, [])

  const toggle = async (s: Schedule) => {
    await api.patch(`/schedules/${s.id}`, { enabled: !s.enabled })
    load()
  }
  const remove = async (id: string) => {
    if (!confirm('Delete this schedule?')) return
    await api.delete(`/schedules/${id}`)
    load()
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Clock className="w-5 h-5 text-accent" />
          <h1 className="text-lg font-semibold">Scheduled scans</h1>
        </div>
        <button
          onClick={() => setShowForm((s) => !s)}
          className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-1.5 rounded-md hover:bg-accent/20 transition-colors"
        >
          {showForm ? <X className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
          {showForm ? 'Cancel' : 'New schedule'}
        </button>
      </div>

      <p className="text-sm text-muted -mt-2">
        Configure once and let scans run on a cron schedule. Pair with an integration to get
        notified automatically when something serious is found.
      </p>

      {showForm && <AddForm onCreated={() => { setShowForm(false); load() }} />}

      <div className="space-y-3">
        {loading ? (
          <div className="text-xs text-muted py-8 text-center">Loading…</div>
        ) : !items.length ? (
          <div className="text-xs text-muted py-8 text-center">
            No scheduled scans yet. Create one to run scans automatically.
          </div>
        ) : (
          items.map((s) => (
            <div
              key={s.id}
              className="bg-surface border border-border rounded-lg p-4 flex items-center justify-between gap-4"
            >
              <div className="min-w-0">
                <p className="text-white">{s.name}</p>
                <p className="text-xs text-muted">
                  {cronLabel(s.cron_expression)} · {s.asset_ids.length} asset
                  {s.asset_ids.length === 1 ? '' : 's'} · {s.tools.join(', ')}
                </p>
                <div className="flex items-center gap-3 mt-1 text-xs text-muted">
                  {s.last_run ? (
                    <span className="flex items-center gap-1">
                      {s.last_run.status === 'failed' ? (
                        <XCircle className="w-3 h-3 text-severity-critical" />
                      ) : (
                        <CheckCircle className="w-3 h-3 text-mode-auto" />
                      )}
                      Last run {formatDistanceToNow(new Date(s.last_run.started_at))} ago
                    </span>
                  ) : (
                    <span>Never run yet</span>
                  )}
                  {s.enabled && s.next_run && (
                    <span>· Next {formatDistanceToNow(new Date(s.next_run), { addSuffix: true })}</span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <button
                  onClick={() => toggle(s)}
                  className={cn(
                    'text-xs px-2 py-1 rounded transition-colors',
                    s.enabled ? 'bg-mode-auto/10 text-mode-auto' : 'bg-white/5 text-muted',
                  )}
                >
                  {s.enabled ? 'Enabled' : 'Disabled'}
                </button>
                <button
                  onClick={() => remove(s.id)}
                  className="text-muted hover:text-severity-critical transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

function AddForm({ onCreated }: { onCreated: () => void }) {
  const { assets, loading: assetsLoading } = useAssets()
  const [name, setName] = useState('')
  const [assetIds, setAssetIds] = useState<string[]>([])
  const [preset, setPreset] = useState(CRON_PRESETS[0].value)
  const [customCron, setCustomCron] = useState('0 2 * * *')
  const [tools, setTools] = useState<string[]>(['nuclei', 'nmap'])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const toggleIn = (list: string[], v: string) =>
    list.includes(v) ? list.filter((x) => x !== v) : [...list, v]

  const submit = async () => {
    setError('')
    if (!name.trim()) return setError('Name is required')
    if (!assetIds.length) return setError('Select at least one asset')
    if (!tools.length) return setError('Select at least one tool')
    const cron = preset === 'custom' ? customCron.trim() : preset
    setSaving(true)
    try {
      await api.post('/schedules', {
        name: name.trim(),
        asset_ids: assetIds,
        cron_expression: cron,
        tools,
        enabled: true,
      })
      onCreated()
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Could not create schedule'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="bg-surface border border-border rounded-lg p-4 space-y-4">
      <div>
        <label className={label}>Name</label>
        <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="Nightly production scan" />
      </div>

      <div>
        <div className="flex items-center justify-between">
          <label className={label}>Assets</label>
          {!assetsLoading && assets.length > 0 && (
            <button
              type="button"
              onClick={() =>
                setAssetIds((l) => (l.length === assets.length ? [] : assets.map((a) => a.id)))
              }
              className="text-xs text-accent hover:text-accent/80 mb-1"
            >
              {assetIds.length === assets.length ? 'Deselect all' : 'Select all'}
            </button>
          )}
        </div>
        {assetsLoading ? (
          <p className="text-xs text-muted">Loading assets…</p>
        ) : !assets.length ? (
          <p className="text-xs text-muted">No assets yet — add one first.</p>
        ) : (
          <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto">
            {assets.map((a) => (
              <label key={a.id} className="flex items-center gap-2 text-sm text-white cursor-pointer">
                <input
                  type="checkbox"
                  checked={assetIds.includes(a.id)}
                  onChange={() => setAssetIds((l) => toggleIn(l, a.id))}
                  className="accent-accent"
                />
                <span className="truncate">{a.name} <span className="text-muted text-xs">{a.host}</span></span>
              </label>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className={label}>Frequency</label>
          <select className={input} value={preset} onChange={(e) => setPreset(e.target.value)}>
            {CRON_PRESETS.map((p) => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </select>
        </div>
        {preset === 'custom' && (
          <div>
            <label className={label}>Cron expression</label>
            <input className={input} value={customCron} onChange={(e) => setCustomCron(e.target.value)} placeholder="0 2 * * *" />
          </div>
        )}
      </div>

      <div>
        <label className={label}>Tools</label>
        <div className="flex gap-4">
          {ALL_TOOLS.map((t) => (
            <label key={t} className="flex items-center gap-2 text-sm text-white cursor-pointer capitalize">
              <input
                type="checkbox"
                checked={tools.includes(t)}
                onChange={() => setTools((l) => toggleIn(l, t))}
                className="accent-accent"
              />
              {t}
            </label>
          ))}
        </div>
      </div>

      <div className="flex items-center justify-end gap-3">
        <button
          onClick={submit}
          disabled={saving}
          className="bg-accent text-bg font-medium text-sm px-4 py-1.5 rounded-md hover:bg-accent/90 disabled:opacity-50 transition-colors"
        >
          {saving ? 'Saving…' : 'Create schedule'}
        </button>
      </div>

      {error && <p className="text-xs text-severity-high">{error}</p>}
    </div>
  )
}
