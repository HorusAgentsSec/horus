import { useEffect, useState } from 'react'
import { formatDistanceToNow } from 'date-fns'
import cronstrue from 'cronstrue'
import {
  Clock, Plus, Trash2, X, CheckCircle, XCircle, Pencil,
  Swords, Fish,
} from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { useAssets } from '../hooks/useAssets'
import { cn } from '../lib/utils'
import { Modal } from '../components/Modal'
import { Select } from '../components/ui/Select'
import { useConfirm } from '../components/ui/ConfirmProvider'

// ── shared types ──────────────────────────────────────────────────────────────

interface LastRun {
  status: string
  started_at: string
  detail?: Record<string, unknown>
}

interface ScanSchedule {
  id: string
  name: string
  asset_ids: string[]
  cron_expression: string
  tools: string[]
  enabled: boolean
  last_run: LastRun | null
  next_run: string | null
}

interface AdversarialSchedule {
  id: string
  name: string
  cron_expression: string
  enabled: boolean
  last_run: LastRun | null
  next_run: string | null
}

interface PhishingSchedule {
  id: string
  name: string
  cron_expression: string
  objective: 'click' | 'credentials' | 'report'
  contact_ids: string[]
  context_asset_ids: string[]
  enabled: boolean
  last_run: LastRun | null
  next_run: string | null
}

interface Contact { id: string; name: string; email: string; department: string | null }

// ── shared constants ──────────────────────────────────────────────────────────

const CRON_PRESETS = [
  { label: 'Daily at 02:00',     value: '0 2 * * *' },
  { label: 'Every 6 hours',      value: '0 */6 * * *' },
  { label: 'Weekly (Mon 03:00)', value: '0 3 * * 1' },
  { label: 'Monthly (1st 04:00)', value: '0 4 1 * *' },
  { label: 'Custom…',            value: 'custom' },
]

const OBJECTIVE_LABELS: Record<string, string> = {
  click: 'Click test', credentials: 'Credential lure', report: 'Reporting drill',
}

const inputCls = 'bg-bg border border-border text-sm text-white rounded px-3 py-1.5 w-full focus:outline-none focus:border-accent placeholder:text-muted/60'
const labelCls = 'text-xs text-muted mb-1 block'

function cronLabel(cron: string) {
  const preset = CRON_PRESETS.find((p) => p.value === cron)
  if (preset) return preset.label
  try {
    return cronstrue.toString(cron, { use24HourTimeFormat: true })
  } catch {
    return cron
  }
}
function cronLabelWithRaw(cron: string) {
  const label = cronLabel(cron)
  return label !== cron ? `${label} (${cron})` : cron
}
function guessPreset(cron: string) {
  return CRON_PRESETS.find((p) => p.value === cron && p.value !== 'custom')?.value ?? 'custom'
}

function RunMeta({ s }: { s: { last_run: LastRun | null; next_run: string | null; enabled: boolean } }) {
  return (
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
  )
}

// ── tab type ──────────────────────────────────────────────────────────────────

type Tab = 'scans' | 'redblue' | 'phishing'

// ── main page ─────────────────────────────────────────────────────────────────

export default function Schedules() {
  const [tab, setTab] = useState<Tab>('scans')

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center gap-2">
        <Clock className="w-5 h-5 text-accent" />
        <h1 className="text-lg font-semibold">Schedules</h1>
      </div>
      <p className="text-sm text-muted -mt-2">
        Configure recurring runs for scans, adversarial cycles, and phishing simulations.
      </p>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-white/10">
        {([
          { id: 'scans',    label: 'Scans',    icon: <Clock className="w-3.5 h-3.5" /> },
          { id: 'redblue',  label: 'Red / Blue', icon: <Swords className="w-3.5 h-3.5" /> },
          { id: 'phishing', label: 'Phishing', icon: <Fish className="w-3.5 h-3.5" /> },
        ] as { id: Tab; label: string; icon: React.ReactNode }[]).map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              'flex items-center gap-1.5 px-4 py-2 text-sm border-b-2 -mb-px transition-colors',
              tab === t.id
                ? 'border-accent text-accent'
                : 'border-transparent text-white/40 hover:text-white/70',
            )}
          >
            {t.icon}{t.label}
          </button>
        ))}
      </div>

      {tab === 'scans'    && <ScansTab />}
      {tab === 'redblue'  && <RedBlueTab />}
      {tab === 'phishing' && <PhishingTab />}
    </div>
  )
}

// ── scans tab (unchanged logic) ───────────────────────────────────────────────

const ALL_TOOLS = ['nuclei', 'nmap'] as const

function ScansTab() {
  const confirm = useConfirm()
  const [items, setItems]       = useState<ScanSchedule[]>([])
  const [loading, setLoading]   = useState(true)
  const [showAdd, setShowAdd]   = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)

  const load = () => {
    setLoading(true)
    api.get<ScanSchedule[]>('/schedules').then(setItems).finally(() => setLoading(false))
  }
  useEffect(load, [])

  const toggle = async (s: ScanSchedule) => {
    await api.patch(`/schedules/${s.id}`, { enabled: !s.enabled })
    load()
  }
  const remove = async (id: string) => {
    if (!(await confirm({ message: 'Delete this schedule?', danger: true, confirmLabel: 'Delete' }))) return
    await api.delete(`/schedules/${id}`)
    load()
  }

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <button
          onClick={() => { setShowAdd((v) => !v); setEditingId(null) }}
          className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-1.5 rounded-md hover:bg-accent/20 transition-colors"
        >
          {showAdd ? <X className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
          {showAdd ? 'Cancel' : 'New schedule'}
        </button>
      </div>

      {showAdd && (
        <ScanScheduleForm onSaved={() => { setShowAdd(false); load() }} onCancel={() => setShowAdd(false)} />
      )}

      {loading ? (
        <div className="text-xs text-muted py-8 text-center">Loading…</div>
      ) : !items.length ? (
        <div className="text-xs text-muted py-8 text-center">No scheduled scans yet.</div>
      ) : (
        items.map((s) => (
          <div key={s.id}>
            <div className="bg-surface border border-border rounded-lg p-4 flex items-center justify-between gap-4">
              <div className="min-w-0">
                <p className="text-white">{s.name}</p>
                <p className="text-xs text-muted">
                  {cronLabel(s.cron_expression)} · {s.asset_ids.length} asset{s.asset_ids.length !== 1 ? 's' : ''} · {s.tools.join(', ')}
                </p>
                <RunMeta s={s} />
              </div>
              <ScheduleActions
                enabled={s.enabled}
                onToggle={() => toggle(s)}
                onEdit={() => { setShowAdd(false); setEditingId((id) => id === s.id ? null : s.id) }}
                onDelete={() => remove(s.id)}
                editing={editingId === s.id}
              />
            </div>
            {editingId === s.id && (
              <ScanScheduleForm
                initial={s}
                onSaved={() => { setEditingId(null); load() }}
                onCancel={() => setEditingId(null)}
              />
            )}
          </div>
        ))
      )}
    </div>
  )
}

function ScanScheduleForm({ initial, onSaved, onCancel }: { initial?: ScanSchedule; onSaved: () => void; onCancel: () => void }) {
  const { assets, loading: assetsLoading } = useAssets()
  const [name, setName]     = useState(initial?.name ?? '')
  const [assetIds, setAssetIds] = useState<string[]>(initial?.asset_ids ?? [])
  const [tools, setTools]   = useState<string[]>(initial?.tools ?? ['nuclei', 'nmap'])
  const [preset, setPreset] = useState(guessPreset(initial?.cron_expression ?? '0 2 * * *'))
  const [customCron, setCustomCron] = useState(initial?.cron_expression ?? '0 2 * * *')
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState('')
  const isEdit = !!initial

  const toggleIn = (list: string[], v: string) => list.includes(v) ? list.filter((x) => x !== v) : [...list, v]

  const submit = async () => {
    setError('')
    if (!name.trim()) return setError('Name is required')
    if (!assetIds.length) return setError('Select at least one asset')
    if (!tools.length) return setError('Select at least one tool')
    const cron = preset === 'custom' ? customCron.trim() : preset
    setSaving(true)
    try {
      const payload = { name: name.trim(), asset_ids: assetIds, cron_expression: cron, tools }
      if (isEdit) await api.patch(`/schedules/${initial.id}`, payload)
      else await api.post('/schedules', { ...payload, enabled: true })
      onSaved()
    } catch (e) {
      setError(friendlyErrorMessage(e))
    } finally { setSaving(false) }
  }

  return (
    <Modal
      open
      onClose={onCancel}
      title={initial ? `Editing "${initial.name}"` : 'New scan schedule'}
      className="max-w-lg"
    >
      <div className="space-y-4">
        <div>
          <label className={labelCls}>Name</label>
          <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="Nightly production scan" />
        </div>
        <div>
          <div className="flex items-center justify-between">
            <label className={labelCls}>Assets</label>
            {!assetsLoading && assets.length > 0 && (
              <button type="button" onClick={() => setAssetIds((l) => l.length === assets.length ? [] : assets.map((a) => a.id))} className="text-xs text-accent hover:text-accent/80 mb-1">
                {assetIds.length === assets.length ? 'Deselect all' : 'Select all'}
              </button>
            )}
          </div>
          {assetsLoading ? <p className="text-xs text-muted">Loading assets…</p> : !assets.length ? <p className="text-xs text-muted">No assets yet.</p> : (
            <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto">
              {assets.map((a) => (
                <label key={a.id} className="flex items-center gap-2 text-sm text-white cursor-pointer">
                  <input type="checkbox" checked={assetIds.includes(a.id)} onChange={() => setAssetIds((l) => toggleIn(l, a.id))} className="accent-accent" />
                  <span className="truncate">{a.name} <span className="text-muted text-xs">{a.host}</span></span>
                </label>
              ))}
            </div>
          )}
        </div>
        <CronField preset={preset} customCron={customCron} onPreset={setPreset} onCustom={setCustomCron} />
        <div>
          <label className={labelCls}>Tools</label>
          <div className="flex gap-4">
            {ALL_TOOLS.map((t) => (
              <label key={t} className="flex items-center gap-2 text-sm text-white cursor-pointer capitalize">
                <input type="checkbox" checked={tools.includes(t)} onChange={() => setTools((l) => toggleIn(l, t))} className="accent-accent" />
                {t}
              </label>
            ))}
          </div>
        </div>
        <FormFooter saving={saving} isEdit={isEdit} onCancel={onCancel} onSubmit={submit} error={error} />
      </div>
    </Modal>
  )
}

// ── red/blue tab ──────────────────────────────────────────────────────────────

function RedBlueTab() {
  const confirm = useConfirm()
  const [items, setItems]       = useState<AdversarialSchedule[]>([])
  const [loading, setLoading]   = useState(true)
  const [showAdd, setShowAdd]   = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)

  const load = () => {
    setLoading(true)
    api.get<AdversarialSchedule[]>('/adversarial/schedules', 0).then(setItems).finally(() => setLoading(false))
  }
  useEffect(load, [])

  const toggle = async (s: AdversarialSchedule) => {
    await api.patch(`/adversarial/schedules/${s.id}`, { enabled: !s.enabled })
    load()
  }
  const remove = async (id: string) => {
    if (!(await confirm({ message: 'Delete this schedule?', danger: true, confirmLabel: 'Delete' }))) return
    await api.delete(`/adversarial/schedules/${id}`)
    load()
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-white/40">
        Each run executes a full Red→Blue adversarial cycle for your organisation and records findings in the Adversarial section.
      </p>
      <div className="flex justify-end">
        <button
          onClick={() => { setShowAdd((v) => !v); setEditingId(null) }}
          className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-1.5 rounded-md hover:bg-accent/20 transition-colors"
        >
          {showAdd ? <X className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
          {showAdd ? 'Cancel' : 'New schedule'}
        </button>
      </div>

      {showAdd && (
        <SimpleScheduleForm
          title="New Red/Blue schedule"
          onSaved={async (name, cron) => { await api.post('/adversarial/schedules', { name, cron_expression: cron }); setShowAdd(false); load() }}
          onCancel={() => setShowAdd(false)}
        />
      )}

      {loading ? (
        <div className="text-xs text-muted py-8 text-center">Loading…</div>
      ) : !items.length ? (
        <div className="text-xs text-muted py-8 text-center">No Red/Blue schedules yet.</div>
      ) : (
        items.map((s) => (
          <div key={s.id}>
            <div className="bg-surface border border-border rounded-lg p-4 flex items-center justify-between gap-4">
              <div className="min-w-0">
                <p className="text-white">{s.name}</p>
                <p className="text-xs text-muted">{cronLabelWithRaw(s.cron_expression)}</p>
                <RunMeta s={s} />
              </div>
              <ScheduleActions
                enabled={s.enabled}
                onToggle={() => toggle(s)}
                onEdit={() => { setShowAdd(false); setEditingId((id) => id === s.id ? null : s.id) }}
                onDelete={() => remove(s.id)}
                editing={editingId === s.id}
              />
            </div>
            {editingId === s.id && (
              <SimpleScheduleForm
                title={`Editing "${s.name}"`}
                initialName={s.name}
                initialCron={s.cron_expression}
                onSaved={async (name, cron) => { await api.patch(`/adversarial/schedules/${s.id}`, { name, cron_expression: cron }); setEditingId(null); load() }}
                onCancel={() => setEditingId(null)}
              />
            )}
          </div>
        ))
      )}
    </div>
  )
}

// ── phishing tab ──────────────────────────────────────────────────────────────

function PhishingTab() {
  const confirm = useConfirm()
  const [items, setItems]       = useState<PhishingSchedule[]>([])
  const [loading, setLoading]   = useState(true)
  const [showAdd, setShowAdd]   = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [contacts, setContacts] = useState<Contact[]>([])

  const load = () => {
    setLoading(true)
    Promise.all([
      api.get<PhishingSchedule[]>('/phishing/schedules', 0),
      api.get<Contact[]>('/phishing/contacts', 0).catch(() => []),
    ]).then(([s, c]) => { setItems(s); setContacts(c) }).finally(() => setLoading(false))
  }
  useEffect(load, [])

  const toggle = async (s: PhishingSchedule) => {
    await api.patch(`/phishing/schedules/${s.id}`, { enabled: !s.enabled })
    load()
  }
  const remove = async (id: string) => {
    if (!(await confirm({ message: 'Delete this schedule?', danger: true, confirmLabel: 'Delete' }))) return
    await api.delete(`/phishing/schedules/${id}`)
    load()
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-white/40">
        Recurring phishing simulations. Each run creates a new campaign and sends emails to the selected contacts.
      </p>
      <div className="flex justify-end">
        <button
          onClick={() => { setShowAdd((v) => !v); setEditingId(null) }}
          className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-1.5 rounded-md hover:bg-accent/20 transition-colors"
        >
          {showAdd ? <X className="w-4 h-4" /> : <Plus className="w-4 h-4" />}
          {showAdd ? 'Cancel' : 'New schedule'}
        </button>
      </div>

      {showAdd && (
        <PhishingScheduleForm
          contacts={contacts}
          onSaved={() => { setShowAdd(false); load() }}
          onCancel={() => setShowAdd(false)}
        />
      )}

      {loading ? (
        <div className="text-xs text-muted py-8 text-center">Loading…</div>
      ) : !items.length ? (
        <div className="text-xs text-muted py-8 text-center">No phishing schedules yet.</div>
      ) : (
        items.map((s) => (
          <div key={s.id}>
            <div className="bg-surface border border-border rounded-lg p-4 flex items-center justify-between gap-4">
              <div className="min-w-0">
                <p className="text-white">{s.name}</p>
                <p className="text-xs text-muted">
                  {cronLabel(s.cron_expression)} · {OBJECTIVE_LABELS[s.objective]} · {s.contact_ids.length} contact{s.contact_ids.length !== 1 ? 's' : ''}
                </p>
                <RunMeta s={s} />
              </div>
              <ScheduleActions
                enabled={s.enabled}
                onToggle={() => toggle(s)}
                onEdit={() => { setShowAdd(false); setEditingId((id) => id === s.id ? null : s.id) }}
                onDelete={() => remove(s.id)}
                editing={editingId === s.id}
              />
            </div>
            {editingId === s.id && (
              <PhishingScheduleForm
                initial={s}
                contacts={contacts}
                onSaved={() => { setEditingId(null); load() }}
                onCancel={() => setEditingId(null)}
              />
            )}
          </div>
        ))
      )}
    </div>
  )
}

function PhishingScheduleForm({
  initial, contacts, onSaved, onCancel,
}: {
  initial?: PhishingSchedule
  contacts: Contact[]
  onSaved: () => void
  onCancel: () => void
}) {
  const { assets } = useAssets()
  const [name, setName]         = useState(initial?.name ?? '')
  const [objective, setObjective] = useState<string>(initial?.objective ?? 'click')
  const [contactIds, setContactIds] = useState<string[]>(initial?.contact_ids ?? [])
  const [assetIds, setAssetIds] = useState<string[]>(initial?.context_asset_ids ?? [])
  const [preset, setPreset]     = useState(guessPreset(initial?.cron_expression ?? '0 2 * * *'))
  const [customCron, setCustomCron] = useState(initial?.cron_expression ?? '0 2 * * *')
  const [saving, setSaving]     = useState(false)
  const [error, setError]       = useState('')
  const isEdit = !!initial

  const toggleId = (list: string[], id: string) => list.includes(id) ? list.filter((x) => x !== id) : [...list, id]

  const submit = async () => {
    setError('')
    if (!name.trim()) return setError('Name is required')
    if (!contactIds.length) return setError('Select at least one contact')
    const cron = preset === 'custom' ? customCron.trim() : preset
    const payload = { name: name.trim(), cron_expression: cron, objective, contact_ids: contactIds, asset_ids: assetIds }
    setSaving(true)
    try {
      if (isEdit) await api.patch(`/phishing/schedules/${initial.id}`, payload)
      else await api.post('/phishing/schedules', payload)
      onSaved()
    } catch (e) { setError(friendlyErrorMessage(e)) }
    finally { setSaving(false) }
  }

  return (
    <Modal
      open
      onClose={onCancel}
      title={initial ? `Editing "${initial.name}"` : 'New phishing schedule'}
      className="max-w-lg"
    >
      <div className="space-y-4">
        <div>
          <label className={labelCls}>Name</label>
          <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="Monthly awareness drill" />
        </div>
        <div>
          <label className={labelCls}>Objective</label>
          <Select
            className="w-full"
            value={objective}
            onValueChange={(v) => setObjective(v)}
            options={Object.entries(OBJECTIVE_LABELS).map(([k, v]) => ({ value: k, label: v }))}
          />
        </div>
        <div>
          <div className="flex items-center justify-between">
            <label className={labelCls}>Contacts ({contactIds.length} selected)</label>
            {contacts.length > 0 && (
              <button type="button" onClick={() => setContactIds(contactIds.length === contacts.length ? [] : contacts.map((c) => c.id))} className="text-xs text-accent hover:text-accent/80 mb-1">
                {contactIds.length === contacts.length ? 'Deselect all' : 'Select all'}
              </button>
            )}
          </div>
          {contacts.length === 0 ? (
            <p className="text-xs text-muted">No contacts yet — add them in the Phishing → Contacts tab first.</p>
          ) : (
            <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto">
              {contacts.map((c) => (
                <label key={c.id} className="flex items-center gap-2 text-sm text-white cursor-pointer">
                  <input type="checkbox" checked={contactIds.includes(c.id)} onChange={() => setContactIds((l) => toggleId(l, c.id))} className="accent-accent" />
                  <span className="truncate">{c.name} <span className="text-muted text-xs">{c.email}</span></span>
                </label>
              ))}
            </div>
          )}
        </div>
        <div>
          <label className={labelCls}>Assets context <span className="text-white/25">(optional — leave empty for all active)</span></label>
          <div className="grid grid-cols-2 gap-2 max-h-32 overflow-y-auto">
            {assets.map((a) => (
              <label key={a.id} className="flex items-center gap-2 text-sm text-white cursor-pointer">
                <input type="checkbox" checked={assetIds.includes(a.id)} onChange={() => setAssetIds((l) => toggleId(l, a.id))} className="accent-accent" />
                <span className="truncate">{a.host || a.name}</span>
              </label>
            ))}
          </div>
        </div>
        <CronField preset={preset} customCron={customCron} onPreset={setPreset} onCustom={setCustomCron} />
        <FormFooter saving={saving} isEdit={isEdit} onCancel={onCancel} onSubmit={submit} error={error} />
      </div>
    </Modal>
  )
}

// ── shared form helpers ───────────────────────────────────────────────────────

function SimpleScheduleForm({
  title, initialName = '', initialCron = '0 2 * * *', onSaved, onCancel,
}: {
  title: string
  initialName?: string
  initialCron?: string
  onSaved: (name: string, cron: string) => Promise<void>
  onCancel: () => void
}) {
  const [name, setName]     = useState(initialName)
  const [preset, setPreset] = useState(guessPreset(initialCron))
  const [customCron, setCustomCron] = useState(initialCron)
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState('')

  const submit = async () => {
    setError('')
    if (!name.trim()) return setError('Name is required')
    const cron = preset === 'custom' ? customCron.trim() : preset
    setSaving(true)
    try { await onSaved(name.trim(), cron) }
    catch (e) { setError(friendlyErrorMessage(e)) }
    finally { setSaving(false) }
  }

  return (
    <Modal open onClose={onCancel} title={title} className="max-w-lg">
      <div className="space-y-4">
        <div>
          <label className={labelCls}>Name</label>
          <input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="Weekly Red/Blue cycle" />
        </div>
        <CronField preset={preset} customCron={customCron} onPreset={setPreset} onCustom={setCustomCron} />
        <FormFooter saving={saving} isEdit={!!initialName} onCancel={onCancel} onSubmit={submit} error={error} />
      </div>
    </Modal>
  )
}

function CronField({ preset, customCron, onPreset, onCustom }: {
  preset: string; customCron: string; onPreset: (v: string) => void; onCustom: (v: string) => void
}) {
  return (
    <div className="grid grid-cols-2 gap-3">
      <div>
        <label className={labelCls}>Frequency</label>
        <Select
          className="w-full"
          value={preset}
          onValueChange={(v) => onPreset(v)}
          options={CRON_PRESETS.map((p) => ({ value: p.value, label: p.label }))}
        />
      </div>
      {preset === 'custom' && (
        <div>
          <label className={labelCls}>Cron expression</label>
          <input className={inputCls} value={customCron} onChange={(e) => onCustom(e.target.value)} placeholder="0 2 * * *" />
        </div>
      )}
    </div>
  )
}

function FormFooter({ saving, isEdit, onCancel, onSubmit, error }: {
  saving: boolean; isEdit: boolean; onCancel: () => void; onSubmit: () => void; error: string
}) {
  return (
    <>
      <div className="flex items-center justify-end gap-3">
        <button onClick={onCancel} className="text-sm text-muted hover:text-white transition-colors">Cancel</button>
        <button
          onClick={onSubmit} disabled={saving}
          className="bg-accent text-bg font-medium text-sm px-4 py-1.5 rounded-md hover:bg-accent/90 disabled:opacity-50 transition-colors"
        >
          {saving ? 'Saving…' : isEdit ? 'Save changes' : 'Create schedule'}
        </button>
      </div>
      {error && <p className="text-xs text-severity-high">{error}</p>}
    </>
  )
}

function ScheduleActions({ enabled, onToggle, onEdit, onDelete, editing }: {
  enabled: boolean; onToggle: () => void; onEdit: () => void; onDelete: () => void; editing: boolean
}) {
  return (
    <div className="flex items-center gap-3 shrink-0">
      <button
        onClick={onToggle}
        className={cn('text-xs px-2 py-1 rounded transition-colors', enabled ? 'bg-mode-auto/10 text-mode-auto' : 'bg-white/5 text-muted')}
      >
        {enabled ? 'Enabled' : 'Disabled'}
      </button>
      <button onClick={onEdit} className={cn('transition-colors', editing ? 'text-accent' : 'text-muted hover:text-white')} title="Edit">
        <Pencil className="w-4 h-4" />
      </button>
      <button onClick={onDelete} className="text-muted hover:text-severity-critical transition-colors" title="Delete">
        <Trash2 className="w-4 h-4" />
      </button>
    </div>
  )
}
