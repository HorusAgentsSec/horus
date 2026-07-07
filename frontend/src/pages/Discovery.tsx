import { useEffect, useState } from 'react'
import { Radar, Plus, Trash2, Play, Globe, Network } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { cn } from '../lib/utils'
import { Modal } from '../components/Modal'
import { Select } from '../components/ui/Select'
import { useConfirm } from '../components/ui/ConfirmProvider'

interface Source {
  id: string
  kind: 'domain' | 'network'
  domain: string | null
  network_cidr: string | null
  cron_expression: string | null
  auto_create_assets: boolean
  enabled: boolean
  last_run_at: string | null
  last_found_count: number | null
}

const FREQ_PRESETS: { label: string; value: string }[] = [
  { label: 'Manual only', value: 'manual' },
  { label: 'Daily at 04:00', value: '0 4 * * *' },
  { label: 'Weekly (Mon 04:00)', value: '0 4 * * 1' },
]

const input =
  'bg-bg border border-border text-sm text-white rounded px-3 py-1.5 w-full focus:outline-none focus:border-accent placeholder:text-muted/60'
const label = 'text-xs text-muted mb-1 block'

function freqLabel(cron: string | null): string {
  if (!cron) return 'Manual only'
  return FREQ_PRESETS.find((p) => p.value === cron)?.label ?? cron
}

export default function Discovery() {
  const confirm = useConfirm()
  const [items, setItems] = useState<Source[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [status, setStatus] = useState<{ id: string; msg: string; ok: boolean } | null>(null)

  const load = () => {
    setLoading(true)
    api.get<Source[]>('/discovery').then(setItems).finally(() => setLoading(false))
  }
  useEffect(load, [])

  const toggle = async (s: Source) => {
    await api.patch(`/discovery/${s.id}`, { enabled: !s.enabled })
    load()
  }
  const remove = async (id: string) => {
    if (!(await confirm({ message: 'Delete this discovery source?', danger: true, confirmLabel: 'Delete' }))) return
    await api.delete(`/discovery/${id}`)
    load()
  }
  const run = async (id: string) => {
    setStatus({ id, msg: 'Discovery started — new assets will appear shortly.', ok: true })
    try {
      await api.post(`/discovery/${id}/run`)
    } catch (e) {
      setStatus({ id, msg: friendlyErrorMessage(e, 'Could not start discovery'), ok: false })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radar className="w-5 h-5 text-accent" />
          <h1 className="text-lg font-semibold">Asset discovery</h1>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-1.5 rounded-md hover:bg-accent/20 transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add domain
        </button>
      </div>

      <p className="text-sm text-muted -mt-2">
        Map a domain's attack surface automatically. Discovery is passive — it uses Certificate
        Transparency logs and DNS to find live subdomains and add them as assets. It never scans;
        scanning stays a separate step.
      </p>

      {showForm && (
        <AddForm onClose={() => setShowForm(false)} onCreated={() => { setShowForm(false); load() }} />
      )}

      <div className="space-y-3">
        {loading ? (
          <div className="text-xs text-muted py-8 text-center">Loading…</div>
        ) : !items.length ? (
          <div className="text-xs text-muted py-8 text-center">
            No discovery sources yet. Add a domain to start mapping your surface.
          </div>
        ) : (
          items.map((s) => (
            <div
              key={s.id}
              className="bg-surface border border-border rounded-lg p-4 flex items-center justify-between gap-4"
            >
              <div className="min-w-0">
                <p className="text-white">
                  {s.kind === 'network' ? s.network_cidr : s.domain}
                  <span className="text-xs text-muted ml-2">
                    {s.kind === 'network' ? 'private network' : 'domain'}
                  </span>
                </p>
                <p className="text-xs text-muted">
                  {freqLabel(s.cron_expression)}
                  {s.last_run_at && ` · last run ${new Date(s.last_run_at).toLocaleString()}`}
                  {s.last_found_count != null && ` · ${s.last_found_count} live found`}
                  {!s.auto_create_assets && ' · preview only'}
                </p>
                {status?.id === s.id && (
                  <p className={cn('text-xs mt-0.5', status.ok ? 'text-mode-auto' : 'text-severity-high')}>
                    {status.msg}
                  </p>
                )}
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <button
                  onClick={() => run(s.id)}
                  className="flex items-center gap-1 text-xs text-muted hover:text-white transition-colors"
                >
                  <Play className="w-3.5 h-3.5" /> Run now
                </button>
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

function AddForm({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [kind, setKind] = useState<'domain' | 'network'>('domain')
  const [domain, setDomain] = useState('')
  const [cidr, setCidr] = useState('')
  const [freq, setFreq] = useState('manual')
  const [autoCreate, setAutoCreate] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const submit = async () => {
    setError('')
    if (kind === 'domain' && !domain.trim()) return setError('Domain is required')
    if (kind === 'network' && !cidr.trim()) return setError('CIDR is required')
    setSaving(true)
    try {
      await api.post('/discovery', {
        kind,
        domain: kind === 'domain' ? domain.trim().toLowerCase() : null,
        network_cidr: kind === 'network' ? cidr.trim() : null,
        cron_expression: freq === 'manual' ? null : freq,
        auto_create_assets: autoCreate,
        enabled: true,
      })
      onCreated()
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Could not create discovery source'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal open onClose={onClose} title="Add domain" className="max-w-lg">
      <div className="space-y-4">
      <div className="flex gap-2">
        {([['domain', Globe], ['network', Network]] as const).map(([k, Icon]) => (
          <button
            key={k}
            onClick={() => setKind(k)}
            className={cn(
              'flex items-center gap-1.5 text-sm px-3 py-1.5 rounded-md capitalize transition-colors',
              kind === k ? 'bg-accent/10 text-accent' : 'text-muted hover:text-white',
            )}
          >
            <Icon className="w-4 h-4" />
            {k === 'domain' ? 'Domain' : 'Private network'}
          </button>
        ))}
      </div>

      {kind === 'domain' ? (
        <div>
          <label className={label}>Domain</label>
          <input className={input} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" />
        </div>
      ) : (
        <div>
          <label className={label}>Private CIDR range</label>
          <input className={input} value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="192.168.1.0/24" />
          <p className="text-xs text-muted mt-1">
            Active ping sweep — only private ranges (RFC1918), max /22. Discovered hosts become
            internal assets.
          </p>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className={label}>Frequency</label>
          <Select
            className="w-full"
            value={freq}
            onValueChange={(v) => setFreq(v)}
            options={FREQ_PRESETS.map((p) => ({ value: p.value, label: p.label }))}
          />
        </div>
        <label className="flex items-center gap-2 text-sm text-white cursor-pointer self-end pb-1.5">
          <input type="checkbox" checked={autoCreate} onChange={(e) => setAutoCreate(e.target.checked)} className="accent-accent" />
          Auto-create assets
        </label>
      </div>
      <div className="flex justify-end gap-2">
        <button onClick={onClose} className="text-sm text-muted hover:text-white px-3 py-1.5">
          Cancel
        </button>
        <button
          onClick={submit}
          disabled={saving}
          className="bg-accent text-bg font-medium text-sm px-4 py-1.5 rounded-md hover:bg-accent/90 disabled:opacity-50 transition-colors"
        >
          {saving ? 'Saving…' : 'Add domain'}
        </button>
      </div>
      {error && <p className="text-xs text-severity-high">{error}</p>}
      </div>
    </Modal>
  )
}
