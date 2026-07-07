import { useEffect, useRef, useState } from 'react'
import {
  Fish, Plus, Target, MousePointerClick, Flag, Users,
  CheckCircle, Loader2, XCircle, ChevronDown, ChevronUp, X,
  Upload, Trash2, UserPlus, Mail,
} from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { cn } from '../lib/utils'

// ── types ──────────────────────────────────────────────────────────────────

interface Campaign {
  id: string
  name: string
  objective: 'click' | 'credentials' | 'report'
  status: 'draft' | 'running' | 'completed' | 'cancelled'
  total: number
  sent: number
  clicked: number
  reported: number
  click_rate: number
  report_rate: number
  created_at: string
  launched_at: string | null
  targets?: PhishTarget[]
}

interface PhishTarget {
  id: string
  employee_name: string
  employee_email: string
  email_subject: string | null
  email_pretext: string | null
  sent_at: string | null
  clicked_at: string | null
  reported_at: string | null
}

interface Contact {
  id: string
  name: string
  email: string
  department: string | null
  created_at: string
}

interface Asset {
  id: string
  name: string
  host: string
  asset_type: string
}

// ── helpers ────────────────────────────────────────────────────────────────

function timeAgo(iso: string) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000
  if (diff < 60)    return 'just now'
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return new Date(iso).toLocaleDateString()
}

const OBJECTIVE_LABELS: Record<string, { label: string; desc: string; color: string }> = {
  click:       { label: 'Click test',       desc: 'Employee clicks the link',              color: 'text-severity-high' },
  credentials: { label: 'Credential lure',  desc: 'Employee prompted to log in',           color: 'text-severity-critical' },
  report:      { label: 'Reporting drill',  desc: 'Employee should recognise & report it', color: 'text-mode-auto' },
}

function StatusBadge({ status }: { status: Campaign['status'] }) {
  const styles: Record<string, string> = {
    draft:     'bg-white/5 text-white/40 border-white/10',
    running:   'bg-accent/15 text-accent border-accent/30',
    completed: 'bg-mode-auto/15 text-mode-auto border-mode-auto/30',
    cancelled: 'bg-white/5 text-white/30 border-white/10',
  }
  return (
    <span className={cn('text-[11px] px-2 py-0.5 rounded-full border uppercase tracking-wider', styles[status] ?? styles.draft)}>
      {status}
    </span>
  )
}

// ── campaign row ───────────────────────────────────────────────────────────

function CampaignRow({ campaign, onSelect }: { campaign: Campaign; onSelect: () => void }) {
  const obj = OBJECTIVE_LABELS[campaign.objective]
  return (
    <button
      onClick={onSelect}
      className="w-full glass glass-hover rounded-lg px-5 py-4 flex items-center gap-4 text-left"
    >
      <div className="shrink-0">
        {campaign.status === 'running'   && <Loader2 className="w-4 h-4 text-accent animate-spin" />}
        {campaign.status === 'completed' && <CheckCircle className="w-4 h-4 text-mode-auto" />}
        {campaign.status === 'cancelled' && <XCircle className="w-4 h-4 text-white/30" />}
        {campaign.status === 'draft'     && <Fish className="w-4 h-4 text-white/40" />}
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium text-white/90 text-sm truncate">{campaign.name}</span>
          <StatusBadge status={campaign.status} />
          <span className={cn('text-xs', obj.color)}>{obj.label}</span>
        </div>
        <div className="flex items-center gap-4 mt-1 text-[12px] text-white/40">
          <span className="flex items-center gap-1"><Users className="w-3 h-3" />{campaign.total} targets</span>
          {campaign.launched_at && <span>{timeAgo(campaign.launched_at)}</span>}
        </div>
      </div>

      <div className="hidden sm:flex shrink-0 items-center gap-6 text-sm">
        <Metric icon={<MousePointerClick className="w-3 h-3" />} value={campaign.click_rate} label="click" warn={campaign.click_rate > 30} />
        <Metric icon={<Flag className="w-3 h-3" />} value={campaign.report_rate} label="report" />
      </div>
    </button>
  )
}

function Metric({ icon, value, label, warn }: { icon: React.ReactNode; value: number; label: string; warn?: boolean }) {
  return (
    <div className="text-center">
      <div className={cn('flex items-center gap-1', warn ? 'text-severity-high' : 'text-white/60')}>
        {icon}
        <span className="font-semibold">{value}%</span>
      </div>
      <div className="text-[10px] text-white/30 mt-0.5">{label}</div>
    </div>
  )
}

// ── campaign detail drawer ─────────────────────────────────────────────────

function CampaignDetail({ campaign, onClose }: { campaign: Campaign; onClose: () => void }) {
  const obj = OBJECTIVE_LABELS[campaign.objective]
  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div className="relative w-full max-w-2xl glass border-l border-white/10 flex flex-col h-full overflow-y-auto">
        <div className="sticky top-0 glass border-b border-white/10 px-6 py-4 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="font-semibold text-white truncate max-w-[16rem] sm:max-w-none">{campaign.name}</h2>
              <StatusBadge status={campaign.status} />
            </div>
            <p className="text-xs text-white/40 mt-0.5">
              <span className={obj.color}>{obj.label}</span>
              {campaign.launched_at && <> · Launched {timeAgo(campaign.launched_at)}</>}
            </p>
          </div>
          <button onClick={onClose} className="p-2 rounded-md hover:bg-white/10 text-white/40">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 px-6 py-4 border-b border-white/10">
          <StatCard label="Targets"  value={campaign.total}       />
          <StatCard label="Sent"     value={campaign.sent}        />
          <StatCard label="Clicked"  value={`${campaign.click_rate}%`}  warn={campaign.click_rate > 30} />
          <StatCard label="Reported" value={`${campaign.report_rate}%`} />
        </div>

        <div className="flex-1 px-6 py-4">
          <h3 className="text-xs uppercase tracking-wider text-white/40 mb-3">Targets</h3>
          {!campaign.targets || campaign.targets.length === 0 ? (
            <p className="text-white/30 text-sm">No targets yet.</p>
          ) : (
            <div className="space-y-2">
              {campaign.targets.map((t) => <TargetRow key={t.id} target={t} />)}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, warn }: { label: string; value: string | number; warn?: boolean }) {
  return (
    <div className="glass rounded-lg p-3 text-center">
      <p className="text-[10px] text-white/40 uppercase tracking-wide">{label}</p>
      <p className={cn('text-xl font-semibold mt-1', warn ? 'text-severity-high' : '')}>{value}</p>
    </div>
  )
}

function TargetRow({ target }: { target: PhishTarget }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="glass rounded-lg">
      <button
        className="w-full px-4 py-3 flex items-center gap-3 text-left flex-wrap sm:flex-nowrap"
        onClick={() => setOpen(!open)}
      >
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-white/80 truncate">{target.employee_name}</div>
          <div className="text-xs text-white/40 truncate">{target.employee_email}</div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {target.sent_at     && <StatusDot color="text-white/40" label="Sent" />}
          {target.clicked_at  && <StatusDot color="text-severity-high" label="Clicked" />}
          {target.reported_at && <StatusDot color="text-mode-auto" label="Reported" />}
          {!target.sent_at    && <span className="text-[11px] text-white/20">Pending</span>}
        </div>
        {target.email_pretext && (
          open ? <ChevronUp className="w-3 h-3 text-white/30" /> : <ChevronDown className="w-3 h-3 text-white/30" />
        )}
      </button>
      {open && target.email_pretext && (
        <div className="px-4 pb-3 text-xs text-white/50 border-t border-white/5 pt-2">
          <strong className="text-white/40">Pretext:</strong> {target.email_pretext}
          {target.email_subject && (
            <div className="mt-1"><strong className="text-white/40">Subject:</strong> {target.email_subject}</div>
          )}
        </div>
      )}
    </div>
  )
}

function StatusDot({ color, label }: { color: string; label: string }) {
  return (
    <span className={cn('text-[11px] px-1.5 py-0.5 rounded border border-current/30 bg-current/10', color)}>
      {label}
    </span>
  )
}

// ── contacts tab ───────────────────────────────────────────────────────────

function ContactsTab() {
  const [contacts, setContacts] = useState<Contact[]>([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')
  const [showAdd, setShowAdd]   = useState(false)
  const [showImport, setShowImport] = useState(false)

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const data = await api.get<Contact[]>('/phishing/contacts', 0)
      setContacts(data)
    } catch (e: any) {
      setError(friendlyErrorMessage(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const remove = async (id: string) => {
    try {
      await api.delete(`/phishing/contacts/${id}`)
      setContacts((prev) => prev.filter((c) => c.id !== id))
    } catch (e: any) {
      setError(friendlyErrorMessage(e))
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-white/40">{contacts.length} contact{contacts.length !== 1 ? 's' : ''}</p>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowImport(true)}
            className="flex items-center gap-1.5 text-sm px-3 py-1.5 glass glass-hover rounded-lg text-white/60"
          >
            <Upload className="w-3.5 h-3.5" /> Import CSV
          </button>
          <button
            onClick={() => setShowAdd(true)}
            className="btn-primary flex items-center gap-1.5 text-sm px-3 py-1.5"
          >
            <UserPlus className="w-3.5 h-3.5" /> Add contact
          </button>
        </div>
      </div>

      {error && <p className="text-severity-high text-sm">{error}</p>}

      {loading ? (
        <div className="flex items-center gap-2 text-muted text-sm">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading…
        </div>
      ) : contacts.length === 0 ? (
        <div className="glass rounded-xl p-10 text-center">
          <Mail className="w-8 h-8 text-white/20 mx-auto mb-3" />
          <p className="text-white/40 text-sm">No contacts yet.</p>
          <p className="text-white/25 text-xs mt-1">Add contacts manually or import a CSV with name and email columns.</p>
        </div>
      ) : (
        <div className="glass rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 text-[11px] text-white/30 uppercase tracking-wider">
                <th className="text-left px-4 py-3">Name</th>
                <th className="text-left px-4 py-3">Email</th>
                <th className="text-left px-4 py-3">Department</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {contacts.map((c, i) => (
                <tr key={c.id} className={cn('border-b border-white/5 last:border-0', i % 2 === 0 ? '' : 'bg-white/[0.02]')}>
                  <td className="px-4 py-3 text-white/80 font-medium">{c.name}</td>
                  <td className="px-4 py-3 text-white/50">{c.email}</td>
                  <td className="px-4 py-3 text-white/40">{c.department || '—'}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => remove(c.id)}
                      className="p-1.5 rounded hover:bg-white/10 text-white/20 hover:text-severity-high transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showAdd && (
        <AddContactModal
          onClose={() => setShowAdd(false)}
          onCreated={(c) => { setContacts((prev) => [...prev, c].sort((a, b) => a.name.localeCompare(b.name))); setShowAdd(false) }}
        />
      )}
      {showImport && (
        <ImportCsvModal
          onClose={() => setShowImport(false)}
          onImported={load}
        />
      )}
    </div>
  )
}

function AddContactModal({ onClose, onCreated }: { onClose: () => void; onCreated: (c: Contact) => void }) {
  const [name, setName]   = useState('')
  const [email, setEmail] = useState('')
  const [dept, setDept]   = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState('')

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    setError('')
    try {
      const c = await api.post<Contact>('/phishing/contacts', { name, email, department: dept || null })
      onCreated(c)
    } catch (e: any) {
      setError(friendlyErrorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <form onSubmit={submit} className="relative glass rounded-2xl w-full max-w-sm shadow-2xl p-6 space-y-4">
        <div className="flex items-center justify-between mb-1">
          <h2 className="font-semibold">Add contact</h2>
          <button type="button" onClick={onClose} className="p-1.5 rounded hover:bg-white/10 text-white/40">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div>
          <label className="text-xs text-white/50 uppercase tracking-wide block mb-1">Full name</label>
          <input
            className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-accent"
            value={name} onChange={(e) => setName(e.target.value)}
            placeholder="Jane Doe" required autoFocus
          />
        </div>
        <div>
          <label className="text-xs text-white/50 uppercase tracking-wide block mb-1">Email</label>
          <input
            type="email"
            className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-accent"
            value={email} onChange={(e) => setEmail(e.target.value)}
            placeholder="jane@company.com" required
          />
        </div>
        <div>
          <label className="text-xs text-white/50 uppercase tracking-wide block mb-1">Department <span className="text-white/25">(optional)</span></label>
          <input
            className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-accent"
            value={dept} onChange={(e) => setDept(e.target.value)}
            placeholder="Finance"
          />
        </div>

        {error && <p className="text-severity-high text-xs">{error}</p>}

        <button
          type="submit" disabled={saving || !name.trim() || !email.trim()}
          className="btn-primary w-full text-sm py-2 flex items-center justify-center gap-2 disabled:opacity-40"
        >
          {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
          Add contact
        </button>
      </form>
    </div>
  )
}

function ImportCsvModal({ onClose, onImported }: { onClose: () => void; onImported: () => void }) {
  const [csvText, setCsvText] = useState('')
  const [preview, setPreview] = useState<{ name: string; email: string; department: string }[]>([])
  const [result, setResult]   = useState<{ created: number; skipped: number } | null>(null)
  const [saving, setSaving]   = useState(false)
  const [error, setError]     = useState('')
  const fileRef = useRef<HTMLInputElement>(null)

  const parsePreview = (text: string) => {
    const lines = text.trim().split('\n').filter(Boolean)
    const rows: { name: string; email: string; department: string }[] = []
    for (const line of lines) {
      const cols = line.split(',').map((c) => c.trim().replace(/^"|"$/g, ''))
      const name  = cols[0] || ''
      const email = cols[1] || ''
      const dept  = cols[2] || ''
      if (email.includes('@') && name && name.toLowerCase() !== 'name') {
        rows.push({ name, email, department: dept })
      }
    }
    setPreview(rows)
  }

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const text = ev.target?.result as string
      setCsvText(text)
      parsePreview(text)
    }
    reader.readAsText(file)
  }

  const onTextChange = (text: string) => {
    setCsvText(text)
    parsePreview(text)
  }

  const doImport = async () => {
    setSaving(true)
    setError('')
    try {
      const res = await api.post<{ created: number; skipped: number }>('/phishing/contacts/import', { csv_text: csvText })
      setResult(res)
      onImported()
    } catch (e: any) {
      setError(friendlyErrorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="relative glass rounded-2xl w-full max-w-lg shadow-2xl p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold">Import contacts from CSV</h2>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-white/10 text-white/40">
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-xs text-white/40">
          Expected columns: <code className="bg-white/5 px-1 rounded">name, email, department</code> (department optional).
          Header row is auto-detected and skipped.
        </p>

        {!result && (
          <>
            <div
              className="border-2 border-dashed border-white/10 rounded-xl p-5 text-center cursor-pointer hover:border-accent/40 transition-colors"
              onClick={() => fileRef.current?.click()}
            >
              <Upload className="w-6 h-6 text-white/30 mx-auto mb-2" />
              <p className="text-sm text-white/40">Click to upload a .csv file</p>
              <p className="text-xs text-white/20 mt-1">or paste CSV below</p>
              <input ref={fileRef} type="file" accept=".csv,text/csv" className="hidden" onChange={onFileChange} />
            </div>

            <textarea
              className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-xs font-mono h-28 resize-none focus:outline-none focus:border-accent text-white/60"
              placeholder={"Jane Doe,jane@company.com,Finance\nJohn Smith,john@company.com,HR"}
              value={csvText}
              onChange={(e) => onTextChange(e.target.value)}
            />

            {preview.length > 0 && (
              <div>
                <p className="text-xs text-white/40 mb-2">{preview.length} valid row{preview.length !== 1 ? 's' : ''} detected</p>
                <div className="glass rounded-lg overflow-hidden max-h-40 overflow-y-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-white/10 text-white/30">
                        <th className="text-left px-3 py-2">Name</th>
                        <th className="text-left px-3 py-2">Email</th>
                        <th className="text-left px-3 py-2">Dept.</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.slice(0, 20).map((r, i) => (
                        <tr key={i} className="border-b border-white/5 last:border-0">
                          <td className="px-3 py-1.5 text-white/70">{r.name}</td>
                          <td className="px-3 py-1.5 text-white/50">{r.email}</td>
                          <td className="px-3 py-1.5 text-white/40">{r.department || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {preview.length > 20 && (
                    <p className="text-center text-xs text-white/25 py-2">+{preview.length - 20} more…</p>
                  )}
                </div>
              </div>
            )}

            {error && <p className="text-severity-high text-xs">{error}</p>}

            <button
              onClick={doImport}
              disabled={saving || preview.length === 0}
              className="btn-primary w-full text-sm py-2 flex items-center justify-center gap-2 disabled:opacity-40"
            >
              {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              Import {preview.length > 0 ? `${preview.length} contacts` : ''}
            </button>
          </>
        )}

        {result && (
          <div className="text-center py-4 space-y-2">
            <CheckCircle className="w-10 h-10 text-mode-auto mx-auto" />
            <p className="text-white/80 font-medium">{result.created} contact{result.created !== 1 ? 's' : ''} imported</p>
            {result.skipped > 0 && (
              <p className="text-xs text-white/40">{result.skipped} skipped (duplicate emails)</p>
            )}
            <button onClick={onClose} className="btn-primary text-sm px-6 py-2 mt-2">Done</button>
          </div>
        )}
      </div>
    </div>
  )
}

// ── new campaign wizard ────────────────────────────────────────────────────

const STEPS = ['Setup', 'Assets', 'Targets', 'Review'] as const
type Step = typeof STEPS[number]

interface WizardState {
  name: string
  objective: 'click' | 'credentials' | 'report'
  selectedAssets: string[]
  selectedContacts: Contact[]
}

function NewCampaignModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: () => void
}) {
  const [step, setStep]     = useState<Step>('Setup')
  const [state, setState]   = useState<WizardState>({
    name: '', objective: 'click', selectedAssets: [], selectedContacts: [],
  })
  const [assets, setAssets]     = useState<Asset[]>([])
  const [contacts, setContacts] = useState<Contact[]>([])
  const [submitting, setSubmitting] = useState(false)
  const [error, setError]     = useState('')

  useEffect(() => {
    Promise.all([
      api.get<Asset[]>('/assets?per_page=50', 0).catch(() => []),
      api.get<Contact[]>('/phishing/contacts', 0).catch(() => []),
    ]).then(([a, c]) => {
      setAssets(a)
      setContacts(c)
    })
  }, [])

  const stepIdx = STEPS.indexOf(step)
  const next = () => setStep(STEPS[stepIdx + 1])
  const back = () => setStep(STEPS[stepIdx - 1])

  const canNext = () => {
    if (step === 'Setup')   return state.name.trim().length > 0
    if (step === 'Targets') return state.selectedContacts.length > 0
    return true
  }

  const launch = async () => {
    setError('')
    setSubmitting(true)
    try {
      await api.post('/phishing/campaigns', {
        name:        state.name,
        objective:   state.objective,
        asset_ids:   state.selectedAssets,
        contact_ids: state.selectedContacts.map((c) => c.id),
      })
      onCreated()
      onClose()
    } catch (e: any) {
      setError(friendlyErrorMessage(e))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="relative glass rounded-2xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/10">
          <h2 className="font-semibold">New Phishing Campaign</h2>
          <button onClick={onClose} className="p-1.5 rounded hover:bg-white/10 text-white/40">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex px-6 py-3 gap-1 border-b border-white/5">
          {STEPS.map((s, i) => (
            <div
              key={s}
              className={cn(
                'flex-1 text-center text-xs py-1 rounded',
                i === stepIdx ? 'bg-accent/20 text-accent' :
                i < stepIdx  ? 'text-white/50' : 'text-white/20',
              )}
            >
              {s}
            </div>
          ))}
        </div>

        <div className="px-6 py-5 min-h-[280px]">
          {step === 'Setup' && (
            <StepSetup state={state} onChange={(s) => setState((p) => ({ ...p, ...s }))} />
          )}
          {step === 'Assets' && (
            <StepAssets
              assets={assets}
              selected={state.selectedAssets}
              onToggle={(id) =>
                setState((p) => ({
                  ...p,
                  selectedAssets: p.selectedAssets.includes(id)
                    ? p.selectedAssets.filter((x) => x !== id)
                    : [...p.selectedAssets, id],
                }))
              }
            />
          )}
          {step === 'Targets' && (
            <StepTargets
              contacts={contacts}
              selected={state.selectedContacts}
              onToggle={(c) =>
                setState((p) => ({
                  ...p,
                  selectedContacts: p.selectedContacts.find((x) => x.id === c.id)
                    ? p.selectedContacts.filter((x) => x.id !== c.id)
                    : [...p.selectedContacts, c],
                }))
              }
            />
          )}
          {step === 'Review' && <StepReview state={state} />}
        </div>

        {error && <p className="px-6 pb-2 text-sm text-severity-high">{error}</p>}
        <div className="flex items-center justify-between px-6 py-4 border-t border-white/10">
          <button
            onClick={back}
            disabled={stepIdx === 0}
            className="text-sm text-white/50 hover:text-white disabled:opacity-30"
          >
            Back
          </button>
          {step !== 'Review' ? (
            <button
              onClick={next}
              disabled={!canNext()}
              className="btn-primary text-sm px-5 py-2 disabled:opacity-40"
            >
              Next
            </button>
          ) : (
            <button
              onClick={launch}
              disabled={submitting || state.selectedContacts.length === 0}
              className="btn-primary text-sm px-5 py-2 disabled:opacity-40 flex items-center gap-2"
            >
              {submitting && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
              Launch campaign
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function StepSetup({
  state,
  onChange,
}: {
  state: WizardState
  onChange: (s: Partial<WizardState>) => void
}) {
  return (
    <div className="space-y-5">
      <div>
        <label className="text-xs text-white/50 uppercase tracking-wide block mb-1.5">Campaign name</label>
        <input
          className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-accent"
          placeholder="e.g. Q2 click-rate baseline"
          value={state.name}
          onChange={(e) => onChange({ name: e.target.value })}
          autoFocus
        />
      </div>
      <div>
        <label className="text-xs text-white/50 uppercase tracking-wide block mb-2">Objective</label>
        <div className="space-y-2">
          {(Object.entries(OBJECTIVE_LABELS) as [string, { label: string; desc: string; color: string }][]).map(([key, { label, desc }]) => (
            <button
              key={key}
              onClick={() => onChange({ objective: key as WizardState['objective'] })}
              className={cn(
                'w-full glass rounded-lg px-4 py-3 flex items-start gap-3 text-left border',
                state.objective === key ? 'border-accent/50 bg-accent/10' : 'border-white/5',
              )}
            >
              <div className={cn('w-3.5 h-3.5 rounded-full border mt-0.5 shrink-0',
                state.objective === key ? 'bg-accent border-accent' : 'border-white/30')} />
              <div>
                <div className="text-sm font-medium">{label}</div>
                <div className="text-xs text-white/40 mt-0.5">{desc}</div>
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

function StepAssets({
  assets,
  selected,
  onToggle,
}: {
  assets: Asset[]
  selected: string[]
  onToggle: (id: string) => void
}) {
  return (
    <div>
      <p className="text-xs text-white/40 mb-3">
        Select up to 5 assets to use as lure context (the AI will reference them in the email).
        Leave empty to use all active assets.
      </p>
      <div className="space-y-1.5 max-h-52 overflow-y-auto pr-1">
        {assets.map((a) => {
          const checked = selected.includes(a.id)
          return (
            <button
              key={a.id}
              onClick={() => onToggle(a.id)}
              disabled={!checked && selected.length >= 5}
              className={cn(
                'w-full glass rounded px-3 py-2 flex items-center gap-3 text-left disabled:opacity-40',
                checked ? 'border border-accent/40 bg-accent/5' : 'border border-white/5',
              )}
            >
              <div className={cn('w-3.5 h-3.5 rounded border shrink-0',
                checked ? 'bg-accent border-accent' : 'border-white/30')} />
              <div className="min-w-0">
                <div className="text-sm truncate">{a.host || a.name}</div>
                <div className="text-xs text-white/30">{a.asset_type}</div>
              </div>
            </button>
          )
        })}
        {assets.length === 0 && <p className="text-white/30 text-sm">No assets found.</p>}
      </div>
    </div>
  )
}

function StepTargets({
  contacts,
  selected,
  onToggle,
}: {
  contacts: Contact[]
  selected: Contact[]
  onToggle: (c: Contact) => void
}) {
  const [search, setSearch] = useState('')
  const filtered = contacts.filter((c) =>
    !search || c.name.toLowerCase().includes(search.toLowerCase()) || c.email.toLowerCase().includes(search.toLowerCase())
  )
  const allSelected = contacts.length > 0 && selected.length === contacts.length
  const toggleAll   = () => {
    if (allSelected) contacts.forEach(onToggle)
    else contacts.filter((c) => !selected.find((s) => s.id === c.id)).forEach(onToggle)
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs text-white/40">
          {selected.length > 0 ? `${selected.length} selected` : 'Select targets from your contact list.'}
        </p>
        {contacts.length > 0 && (
          <button onClick={toggleAll} className="text-xs text-accent hover:text-accent/80">
            {allSelected ? 'Deselect all' : 'Select all'}
          </button>
        )}
      </div>

      {contacts.length > 5 && (
        <input
          className="w-full bg-bg border border-border rounded-lg px-3 py-1.5 text-sm mb-2 focus:outline-none focus:border-accent"
          placeholder="Search by name or email…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      )}

      <div className="space-y-1.5 max-h-52 overflow-y-auto pr-1">
        {filtered.map((c) => {
          const checked = !!selected.find((s) => s.id === c.id)
          return (
            <button
              key={c.id}
              onClick={() => onToggle(c)}
              className={cn(
                'w-full glass rounded px-3 py-2 flex items-center gap-3 text-left',
                checked ? 'border border-accent/40 bg-accent/5' : 'border border-white/5',
              )}
            >
              <div className={cn('w-3.5 h-3.5 rounded border shrink-0',
                checked ? 'bg-accent border-accent' : 'border-white/30')} />
              <div className="min-w-0 flex-1">
                <div className="text-sm truncate">{c.name}</div>
                <div className="text-xs text-white/30 truncate">{c.email}</div>
              </div>
              {c.department && (
                <span className="text-[11px] text-white/25 shrink-0">{c.department}</span>
              )}
            </button>
          )
        })}
        {contacts.length === 0 && (
          <p className="text-white/30 text-sm">
            No contacts yet. Add contacts in the <strong className="text-white/50">Contacts</strong> tab first.
          </p>
        )}
        {contacts.length > 0 && filtered.length === 0 && (
          <p className="text-white/30 text-sm">No contacts match your search.</p>
        )}
      </div>
    </div>
  )
}

function StepReview({ state }: { state: WizardState }) {
  const obj = OBJECTIVE_LABELS[state.objective]
  return (
    <div className="space-y-4">
      <div className="glass rounded-lg p-4 space-y-2">
        <Row label="Name"      value={state.name} />
        <Row label="Objective" value={<span className={obj.color}>{obj.label}</span>} />
        <Row label="Assets"    value={state.selectedAssets.length === 0 ? 'All active assets' : `${state.selectedAssets.length} selected`} />
        <Row label="Targets"   value={`${state.selectedContacts.length} contact${state.selectedContacts.length !== 1 ? 's' : ''}`} />
      </div>
      <p className="text-xs text-white/40">
        Launching will generate personalised phishing emails with Claude and send them via SMTP.
        Each email contains a unique tracking link.
      </p>
      {state.selectedContacts.length === 0 && (
        <p className="text-xs text-severity-high">Select at least one target to launch.</p>
      )}
    </div>
  )
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between text-sm">
      <span className="text-white/40">{label}</span>
      <span className="text-white/80">{value}</span>
    </div>
  )
}

// ── main page ──────────────────────────────────────────────────────────────

type Tab = 'campaigns' | 'contacts'

export default function PhishingCampaigns() {
  const [tab, setTab]               = useState<Tab>('campaigns')
  const [campaigns, setCampaigns]   = useState<Campaign[]>([])
  const [loading, setLoading]       = useState(true)
  const [selected, setSelected]     = useState<Campaign | null>(null)
  const [showNew, setShowNew]       = useState(false)
  const [error, setError]           = useState('')

  const load = async () => {
    setLoading(true)
    setError('')
    try {
      const data = await api.get<Campaign[]>('/phishing/campaigns', 0)
      setCampaigns(data)
    } catch (e: any) {
      setError(friendlyErrorMessage(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const openDetail = async (c: Campaign) => {
    try {
      const full = await api.get<Campaign>(`/phishing/campaigns/${c.id}`, 0)
      setSelected(full)
    } catch {
      setSelected(c)
    }
  }

  const totalSent    = campaigns.reduce((s, c) => s + c.sent, 0)
  const totalClicked = campaigns.reduce((s, c) => s + c.clicked, 0)
  const globalRate   = totalSent > 0 ? Math.round(totalClicked / totalSent * 100) : 0

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2">
            <Fish className="w-5 h-5 text-horus-gold" /> Phishing Simulations
          </h1>
          <p className="text-sm text-white/40 mt-0.5">
            Internal awareness campaigns — generated by Claude, tracked per employee.
          </p>
        </div>
        {tab === 'campaigns' && (
          <button
            onClick={() => setShowNew(true)}
            className="btn-primary flex items-center gap-2 text-sm px-4 py-2"
          >
            <Plus className="w-4 h-4" /> New Campaign
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-white/10 pb-0">
        {(['campaigns', 'contacts'] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={cn(
              'px-4 py-2 text-sm capitalize border-b-2 -mb-px transition-colors',
              tab === t
                ? 'border-accent text-accent'
                : 'border-transparent text-white/40 hover:text-white/70',
            )}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === 'contacts' && <ContactsTab />}

      {tab === 'campaigns' && (
        <>
          {/* Global stats */}
          {campaigns.length > 0 && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <SummaryCard icon={<Target className="w-4 h-4" />}        label="Campaigns"   value={campaigns.length} />
              <SummaryCard icon={<Users className="w-4 h-4" />}         label="Emails sent" value={totalSent} />
              <SummaryCard icon={<MousePointerClick className="w-4 h-4" />} label="Click rate" value={`${globalRate}%`}
                warn={globalRate > 30} />
              <SummaryCard icon={<Flag className="w-4 h-4" />}          label="Reported"
                value={`${campaigns.reduce((s, c) => s + c.reported, 0)}`} />
            </div>
          )}

          {error && <p className="text-severity-high text-sm">{error}</p>}

          {loading ? (
            <div className="flex items-center gap-2 text-muted text-sm">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading…
            </div>
          ) : campaigns.length === 0 ? (
            <div className="glass rounded-xl p-10 text-center">
              <Fish className="w-8 h-8 text-white/20 mx-auto mb-3" />
              <p className="text-white/40 text-sm">No campaigns yet.</p>
              <p className="text-white/25 text-xs mt-1">Create your first simulation to measure employee awareness.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {campaigns.map((c) => (
                <CampaignRow key={c.id} campaign={c} onSelect={() => openDetail(c)} />
              ))}
            </div>
          )}
        </>
      )}

      {selected && (
        <CampaignDetail campaign={selected} onClose={() => setSelected(null)} />
      )}

      {showNew && (
        <NewCampaignModal
          onClose={() => setShowNew(false)}
          onCreated={load}
        />
      )}
    </div>
  )
}

function SummaryCard({
  icon, label, value, warn,
}: {
  icon: React.ReactNode; label: string; value: string | number; warn?: boolean
}) {
  return (
    <div className="glass rounded-lg p-4 flex items-center gap-3">
      <div className="text-white/30">{icon}</div>
      <div>
        <p className="text-[10px] text-white/40 uppercase tracking-wide">{label}</p>
        <p className={cn('text-lg font-semibold mt-0.5', warn ? 'text-severity-high' : '')}>{value}</p>
      </div>
    </div>
  )
}
