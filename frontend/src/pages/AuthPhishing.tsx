import { useEffect, useState, type ElementType } from 'react'
import {
  Users, ShieldAlert, Crosshair, Plus, Upload, RefreshCw,
  Mail, CheckCircle2, AlertTriangle, XCircle, ChevronDown,
  Play, Eye, Trash2, BarChart3
} from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { cn } from '../lib/utils'
import { useRole } from '../hooks/useRole'

// ── Types ────────────────────────────────────────────────────────────────────

interface Employee {
  id: string
  email: string
  full_name: string | null
  department: string | null
  karma_score: number
  hibp_checked_at: string | null
  credential_breaches: CredentialBreach[]
}

interface CredentialBreach {
  id: string
  breach_name: string
  breach_date: string | null
  data_classes: string[]
  is_sensitive: boolean
}

interface Campaign {
  id: string
  name: string
  status: 'draft' | 'scheduled' | 'running' | 'completed' | 'cancelled'
  objective: 'click' | 'credentials' | 'report'
  context_asset_ids: string[]
  schedule_cron: string | null
  created_at: string
  launched_at: string | null
  completed_at: string | null
}

interface Asset {
  id: string
  name: string
  asset_type: string
}

interface CampaignResults {
  campaign: Campaign
  summary: {
    total: number
    clicked: number
    entered_credentials: number
    reported: number
    safe: number
  }
  targets: Array<{
    id: string
    employees: { email: string; full_name: string | null; karma_score: number } | null
    email_sent_at: string | null
    link_clicked_at: string | null
    creds_entered_at: string | null
    reported_at: string | null
  }>
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function karmaColor(score: number) {
  if (score >= 80) return 'text-green-400'
  if (score >= 50) return 'text-yellow-400'
  return 'text-red-400'
}

function statusBadge(status: Campaign['status']) {
  const map: Record<Campaign['status'], { label: string; cls: string }> = {
    draft: { label: 'Draft', cls: 'bg-white/10 text-white/60' },
    scheduled: { label: 'Scheduled', cls: 'bg-blue-900/40 text-blue-300' },
    running: { label: 'Running', cls: 'bg-yellow-900/40 text-yellow-300' },
    completed: { label: 'Completed', cls: 'bg-green-900/40 text-green-300' },
    cancelled: { label: 'Cancelled', cls: 'bg-red-900/40 text-red-300' },
  }
  const m = map[status]
  return <span className={cn('text-xs px-2 py-0.5 rounded-full font-medium', m.cls)}>{m.label}</span>
}

function objectiveLabel(obj: Campaign['objective']) {
  return { click: 'Link click', credentials: 'Credential harvest', report: 'Report test' }[obj]
}

// ── Tab: Employees ────────────────────────────────────────────────────────────

function EmployeesTab() {
  const { can } = useRole()
  const [employees, setEmployees] = useState<Employee[]>([])
  const [loading, setLoading] = useState(true)
  const [checkingHibp, setCheckingHibp] = useState(false)
  const [status, setStatus] = useState<{ msg: string; ok: boolean } | null>(null)
  const [showAdd, setShowAdd] = useState(false)
  const [showImport, setShowImport] = useState(false)
  const [newEmail, setNewEmail] = useState('')
  const [newName, setNewName] = useState('')
  const [newDept, setNewDept] = useState('')
  const [csvText, setCsvText] = useState('')
  const [expandedBreaches, setExpandedBreaches] = useState<string | null>(null)

  const load = () => {
    setLoading(true)
    api.get<Employee[]>('/phishing/employees').then(setEmployees).finally(() => setLoading(false))
  }
  useEffect(load, [])

  const addEmployee = async () => {
    if (!newEmail) return
    try {
      await api.post('/phishing/employees', { email: newEmail, full_name: newName || null, department: newDept || null })
      setNewEmail(''); setNewName(''); setNewDept(''); setShowAdd(false)
      load()
      setStatus({ msg: 'Employee added', ok: true })
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    }
  }

  const importCsv = async () => {
    if (!csvText.trim()) return
    try {
      const res = await api.post<{ imported: number; errors: string[] }>('/phishing/employees/import', { csv_text: csvText })
      setCsvText(''); setShowImport(false)
      load()
      setStatus({ msg: `Imported ${res.imported} employees${res.errors.length ? ` (${res.errors.length} errors)` : ''}`, ok: true })
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    }
  }

  const deleteEmployee = async (id: string) => {
    try {
      await api.delete(`/phishing/employees/${id}`)
      load()
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    }
  }

  const runHibpCheck = async () => {
    setCheckingHibp(true)
    setStatus(null)
    try {
      const res = await api.post<{ employees_affected: number; breach_records: number; skipped?: boolean }>('/phishing/hibp/check')
      if (res.skipped) {
        setStatus({ msg: 'HIBP check skipped — configure hibp_api_key in .env', ok: false })
      } else {
        setStatus({ msg: `Check complete: ${res.employees_affected} employees affected, ${res.breach_records} breach records`, ok: true })
      }
      load()
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    } finally {
      setCheckingHibp(false)
    }
  }

  const totalBreaches = employees.reduce((s, e) => s + (e.credential_breaches?.length || 0), 0)
  const atRisk = employees.filter(e => (e.credential_breaches?.length || 0) > 0).length

  return (
    <div className="space-y-4">
      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-3">
        <div className="glass rounded-lg p-4 border border-white/10">
          <p className="text-xs text-white/50 mb-1">Total employees</p>
          <p className="text-2xl font-bold text-horus-ivory">{employees.length}</p>
        </div>
        <div className="glass rounded-lg p-4 border border-white/10">
          <p className="text-xs text-white/50 mb-1">With exposed credentials</p>
          <p className={cn('text-2xl font-bold', atRisk > 0 ? 'text-red-400' : 'text-green-400')}>{atRisk}</p>
        </div>
        <div className="glass rounded-lg p-4 border border-white/10">
          <p className="text-xs text-white/50 mb-1">Total breach records</p>
          <p className={cn('text-2xl font-bold', totalBreaches > 0 ? 'text-yellow-400' : 'text-green-400')}>{totalBreaches}</p>
        </div>
      </div>

      {/* Actions */}
      {status && (
        <div className={cn('text-sm px-3 py-2 rounded border', status.ok ? 'bg-green-900/30 border-green-700/40 text-green-300' : 'bg-red-900/30 border-red-700/40 text-red-300')}>
          {status.msg}
        </div>
      )}

      <div className="flex items-center gap-2">
        {can('admin') && (
          <>
            <button onClick={() => setShowAdd(!showAdd)} className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-horus-lapis hover:bg-horus-lapis/80 text-sm text-white transition-colors">
              <Plus className="w-4 h-4" /> Add employee
            </button>
            <button onClick={() => setShowImport(!showImport)} className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-white/10 hover:bg-white/15 text-sm text-white/70 transition-colors">
              <Upload className="w-4 h-4" /> Import CSV
            </button>
            <button onClick={runHibpCheck} disabled={checkingHibp} className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-white/10 hover:bg-white/15 text-sm text-white/70 transition-colors disabled:opacity-50">
              <RefreshCw className={cn('w-4 h-4', checkingHibp && 'animate-spin')} /> Check HIBP
            </button>
          </>
        )}
      </div>

      {showAdd && (
        <div className="glass border border-white/10 rounded-lg p-4 space-y-3">
          <p className="text-sm font-medium text-white/80">Add employee</p>
          <div className="grid grid-cols-3 gap-2">
            <input value={newEmail} onChange={e => setNewEmail(e.target.value)} placeholder="email@company.com" className="bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-lapis" />
            <input value={newName} onChange={e => setNewName(e.target.value)} placeholder="Full name (optional)" className="bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-lapis" />
            <input value={newDept} onChange={e => setNewDept(e.target.value)} placeholder="Department (optional)" className="bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-lapis" />
          </div>
          <div className="flex gap-2">
            <button onClick={addEmployee} className="px-3 py-1.5 rounded bg-horus-lapis text-white text-sm">Add</button>
            <button onClick={() => setShowAdd(false)} className="px-3 py-1.5 rounded bg-white/10 text-white/60 text-sm">Cancel</button>
          </div>
        </div>
      )}

      {showImport && (
        <div className="glass border border-white/10 rounded-lg p-4 space-y-3">
          <p className="text-sm font-medium text-white/80">Import CSV — columns: <code className="text-horus-gold">email, full_name, department</code></p>
          <textarea value={csvText} onChange={e => setCsvText(e.target.value)} rows={5} placeholder={"email,full_name,department\nalice@bse.eu,Alice Smith,IT\nbob@bse.eu,Bob Jones,Finance"} className="w-full bg-white/5 border border-white/10 rounded px-3 py-2 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-lapis font-mono" />
          <div className="flex gap-2">
            <button onClick={importCsv} className="px-3 py-1.5 rounded bg-horus-lapis text-white text-sm">Import</button>
            <button onClick={() => setShowImport(false)} className="px-3 py-1.5 rounded bg-white/10 text-white/60 text-sm">Cancel</button>
          </div>
        </div>
      )}

      {/* Employee table */}
      {loading ? (
        <p className="text-sm text-white/40 py-8 text-center">Loading employees…</p>
      ) : employees.length === 0 ? (
        <div className="glass border border-white/10 rounded-lg py-12 text-center">
          <Users className="w-8 h-8 text-white/20 mx-auto mb-3" />
          <p className="text-sm text-white/40">No employees yet — add them or import a CSV</p>
        </div>
      ) : (
        <div className="glass border border-white/10 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 text-white/40 text-xs">
                <th className="text-left px-4 py-3">Employee</th>
                <th className="text-left px-4 py-3">Department</th>
                <th className="text-center px-4 py-3">Karma</th>
                <th className="text-center px-4 py-3">Breaches</th>
                <th className="text-left px-4 py-3">Last checked</th>
                {can('admin') && <th className="px-4 py-3" />}
              </tr>
            </thead>
            <tbody>
              {employees.map(emp => (
                <>
                  <tr key={emp.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                    <td className="px-4 py-3">
                      <p className="text-white/90">{emp.full_name || emp.email}</p>
                      {emp.full_name && <p className="text-white/40 text-xs">{emp.email}</p>}
                    </td>
                    <td className="px-4 py-3 text-white/50">{emp.department || '—'}</td>
                    <td className="px-4 py-3 text-center">
                      <span className={cn('font-bold', karmaColor(emp.karma_score))}>{emp.karma_score}</span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      {emp.credential_breaches?.length > 0 ? (
                        <button onClick={() => setExpandedBreaches(expandedBreaches === emp.id ? null : emp.id)} className="flex items-center gap-1 mx-auto text-red-400 hover:text-red-300">
                          <ShieldAlert className="w-4 h-4" />
                          <span className="font-medium">{emp.credential_breaches.length}</span>
                          <ChevronDown className={cn('w-3 h-3 transition-transform', expandedBreaches === emp.id && 'rotate-180')} />
                        </button>
                      ) : (
                        <CheckCircle2 className="w-4 h-4 text-green-400/60 mx-auto" />
                      )}
                    </td>
                    <td className="px-4 py-3 text-white/40 text-xs">
                      {emp.hibp_checked_at ? new Date(emp.hibp_checked_at).toLocaleDateString() : 'Never'}
                    </td>
                    {can('admin') && (
                      <td className="px-4 py-3">
                        <button onClick={() => deleteEmployee(emp.id)} className="text-white/20 hover:text-red-400 transition-colors">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    )}
                  </tr>
                  {expandedBreaches === emp.id && emp.credential_breaches?.length > 0 && (
                    <tr key={`${emp.id}-breaches`} className="bg-red-950/20 border-b border-white/5">
                      <td colSpan={can('admin') ? 6 : 5} className="px-6 py-3">
                        <div className="space-y-1.5">
                          {emp.credential_breaches.map(b => (
                            <div key={b.id} className="flex items-start gap-3 text-xs">
                              <AlertTriangle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />
                              <div>
                                <span className="text-white/80 font-medium">{b.breach_name}</span>
                                {b.breach_date && <span className="text-white/40 ml-2">{b.breach_date}</span>}
                                {b.is_sensitive && <span className="ml-2 text-red-400 font-medium">⚠ Passwords exposed</span>}
                                <div className="text-white/40 mt-0.5">{b.data_classes.join(', ')}</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Tab: Campaigns ────────────────────────────────────────────────────────────

function CampaignsTab() {
  const { can } = useRole()
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [assets, setAssets] = useState<Asset[]>([])
  const [employees, setEmployees] = useState<Employee[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [status, setStatus] = useState<{ msg: string; ok: boolean } | null>(null)
  const [launching, setLaunching] = useState<string | null>(null)
  const [viewResults, setViewResults] = useState<CampaignResults | null>(null)

  // Create form state
  const [name, setName] = useState('')
  const [objective, setObjective] = useState<'click' | 'credentials' | 'report'>('click')
  const [selectedAssets, setSelectedAssets] = useState<string[]>([])
  const [scheduleCron, setScheduleCron] = useState('')

  const load = () => {
    setLoading(true)
    Promise.all([
      api.get<Campaign[]>('/phishing/campaigns'),
      api.get<Asset[]>('/assets'),
      api.get<Employee[]>('/phishing/employees'),
    ]).then(([c, a, e]) => {
      setCampaigns(c)
      setAssets(a)
      setEmployees(e)
    }).finally(() => setLoading(false))
  }
  useEffect(load, [])

  const createCampaign = async () => {
    if (!name) return
    try {
      await api.post('/phishing/campaigns', {
        name,
        objective,
        context_asset_ids: selectedAssets,
        schedule_cron: scheduleCron || null,
      })
      setName(''); setObjective('click'); setSelectedAssets([]); setScheduleCron('')
      setShowCreate(false)
      load()
      setStatus({ msg: 'Campaign created', ok: true })
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    }
  }

  const deleteCampaign = async (id: string) => {
    try {
      await api.delete(`/phishing/campaigns/${id}`)
      load()
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    }
  }

  const launchCampaign = async (id: string) => {
    const employeeIds = employees.map(e => e.id)
    if (employeeIds.length === 0) {
      setStatus({ msg: 'No employees to target — add them first', ok: false })
      return
    }
    setLaunching(id)
    setStatus(null)
    try {
      const res = await api.post<{ targets: number; send_errors: unknown[] }>(`/phishing/campaigns/${id}/launch`, {
        employee_ids: employeeIds,
      })
      setStatus({ msg: `Launched: ${res.targets} emails generated${res.send_errors.length ? ` (${res.send_errors.length} send errors — check SMTP config)` : ''}`, ok: true })
      load()
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    } finally {
      setLaunching(null)
    }
  }

  const loadResults = async (id: string) => {
    try {
      const res = await api.get<CampaignResults>(`/phishing/campaigns/${id}/results`)
      setViewResults(res)
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    }
  }

  return (
    <div className="space-y-4">
      {status && (
        <div className={cn('text-sm px-3 py-2 rounded border', status.ok ? 'bg-green-900/30 border-green-700/40 text-green-300' : 'bg-red-900/30 border-red-700/40 text-red-300')}>
          {status.msg}
        </div>
      )}

      {can('admin') && (
        <button onClick={() => setShowCreate(!showCreate)} className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-horus-lapis hover:bg-horus-lapis/80 text-sm text-white transition-colors">
          <Plus className="w-4 h-4" /> New campaign
        </button>
      )}

      {showCreate && (
        <div className="glass border border-white/10 rounded-lg p-4 space-y-4">
          <p className="text-sm font-medium text-white/80">New phishing campaign</p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-white/50 mb-1 block">Campaign name</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="Q3 VPN awareness" className="w-full bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-lapis" />
            </div>
            <div>
              <label className="text-xs text-white/50 mb-1 block">Objective</label>
              <select value={objective} onChange={e => setObjective(e.target.value as typeof objective)} className="w-full bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-horus-lapis">
                <option value="click">Link click (click-through rate)</option>
                <option value="credentials">Credential harvest (login test)</option>
                <option value="report">Report test (awareness check)</option>
              </select>
            </div>
          </div>

          <div>
            <label className="text-xs text-white/50 mb-2 block">Asset context (the AI uses these to craft realistic lures)</label>
            <div className="flex flex-wrap gap-2">
              {assets.slice(0, 10).map(a => (
                <button
                  key={a.id}
                  onClick={() => setSelectedAssets(prev => prev.includes(a.id) ? prev.filter(x => x !== a.id) : [...prev, a.id])}
                  className={cn('text-xs px-2 py-1 rounded border transition-colors', selectedAssets.includes(a.id) ? 'bg-horus-lapis border-horus-lapis text-white' : 'bg-white/5 border-white/10 text-white/50 hover:text-white/80')}
                >
                  {a.name}
                </button>
              ))}
            </div>
            {assets.length === 0 && <p className="text-xs text-white/30">No assets — add some in the Assets section first</p>}
          </div>

          <div>
            <label className="text-xs text-white/50 mb-1 block">Schedule (cron, optional — leave empty for manual launch)</label>
            <input value={scheduleCron} onChange={e => setScheduleCron(e.target.value)} placeholder="0 9 * * 1  (every Monday at 9:00)" className="w-full bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-lapis font-mono" />
          </div>

          <div className="flex gap-2">
            <button onClick={createCampaign} className="px-3 py-1.5 rounded bg-horus-lapis text-white text-sm">Create</button>
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 rounded bg-white/10 text-white/60 text-sm">Cancel</button>
          </div>
        </div>
      )}

      {loading ? (
        <p className="text-sm text-white/40 py-8 text-center">Loading campaigns…</p>
      ) : campaigns.length === 0 ? (
        <div className="glass border border-white/10 rounded-lg py-12 text-center">
          <Crosshair className="w-8 h-8 text-white/20 mx-auto mb-3" />
          <p className="text-sm text-white/40">No campaigns yet — create one to start training your team</p>
        </div>
      ) : (
        <div className="space-y-2">
          {campaigns.map(c => (
            <div key={c.id} className="glass border border-white/10 rounded-lg p-4 flex items-center gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <p className="text-white/90 font-medium truncate">{c.name}</p>
                  {statusBadge(c.status)}
                </div>
                <p className="text-xs text-white/40">{objectiveLabel(c.objective)} · {c.context_asset_ids.length} assets in context · Created {new Date(c.created_at).toLocaleDateString()}</p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {can('admin') && c.status === 'draft' && (
                  <button
                    onClick={() => launchCampaign(c.id)}
                    disabled={launching === c.id}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-horus-gold/20 hover:bg-horus-gold/30 text-horus-gold text-sm transition-colors disabled:opacity-50"
                  >
                    <Play className="w-3.5 h-3.5" />
                    {launching === c.id ? 'Launching…' : 'Launch'}
                  </button>
                )}
                {(c.status === 'completed' || c.status === 'running') && (
                  <button onClick={() => loadResults(c.id)} className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-white/10 hover:bg-white/15 text-white/70 text-sm transition-colors">
                    <BarChart3 className="w-3.5 h-3.5" /> Results
                  </button>
                )}
                {can('admin') && c.status === 'draft' && (
                  <button onClick={() => deleteCampaign(c.id)} className="text-white/20 hover:text-red-400 transition-colors p-1">
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Results modal */}
      {viewResults && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="glass border border-white/10 rounded-xl w-full max-w-2xl max-h-[80vh] overflow-auto">
            <div className="flex items-center justify-between p-4 border-b border-white/10">
              <h2 className="font-semibold text-white">{viewResults.campaign.name} — Results</h2>
              <button onClick={() => setViewResults(null)} className="text-white/40 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div className="grid grid-cols-4 gap-3">
                {[
                  { label: 'Sent', value: viewResults.summary.total, color: 'text-white/80' },
                  { label: 'Clicked', value: viewResults.summary.clicked, color: 'text-red-400' },
                  { label: 'Creds entered', value: viewResults.summary.entered_credentials, color: 'text-red-500' },
                  { label: 'Reported', value: viewResults.summary.reported, color: 'text-green-400' },
                ].map(s => (
                  <div key={s.label} className="glass border border-white/10 rounded-lg p-3 text-center">
                    <p className="text-xs text-white/40 mb-1">{s.label}</p>
                    <p className={cn('text-2xl font-bold', s.color)}>{s.value}</p>
                  </div>
                ))}
              </div>
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-white/30 border-b border-white/10">
                    <th className="text-left py-2">Employee</th>
                    <th className="text-center py-2">Sent</th>
                    <th className="text-center py-2">Clicked</th>
                    <th className="text-center py-2">Creds</th>
                    <th className="text-center py-2">Reported</th>
                    <th className="text-center py-2">Karma</th>
                  </tr>
                </thead>
                <tbody>
                  {viewResults.targets.map(t => (
                    <tr key={t.id} className="border-b border-white/5">
                      <td className="py-2 text-white/70">{t.employees?.full_name || t.employees?.email}</td>
                      <td className="py-2 text-center">{t.email_sent_at ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 mx-auto" /> : <XCircle className="w-3.5 h-3.5 text-white/20 mx-auto" />}</td>
                      <td className="py-2 text-center">{t.link_clicked_at ? <AlertTriangle className="w-3.5 h-3.5 text-red-400 mx-auto" /> : <span className="text-white/20">—</span>}</td>
                      <td className="py-2 text-center">{t.creds_entered_at ? <AlertTriangle className="w-3.5 h-3.5 text-red-500 mx-auto" /> : <span className="text-white/20">—</span>}</td>
                      <td className="py-2 text-center">{t.reported_at ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 mx-auto" /> : <span className="text-white/20">—</span>}</td>
                      <td className="py-2 text-center">
                        <span className={cn('font-bold', karmaColor(t.employees?.karma_score ?? 100))}>{t.employees?.karma_score ?? '—'}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

type Tab = 'employees' | 'campaigns'

export default function AuthPhishing() {
  const [tab, setTab] = useState<Tab>('employees')

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-horus-ivory flex items-center gap-2">
          <Mail className="w-5 h-5 text-horus-gold" />
          AuthPhishing
        </h1>
        <p className="text-sm text-white/40 mt-1">
          Human attack surface — credential breach monitoring &amp; contextual phishing simulations
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-white/10 pb-0">
        {([
          { id: 'employees', label: 'Employees & Breaches', icon: Users },
          { id: 'campaigns', label: 'Phishing Campaigns', icon: Crosshair },
        ] as { id: Tab; label: string; icon: ElementType }[]).map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              'flex items-center gap-2 px-4 py-2 text-sm border-b-2 -mb-px transition-colors',
              tab === id
                ? 'border-horus-gold text-horus-gold'
                : 'border-transparent text-white/50 hover:text-white/80',
            )}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {tab === 'employees' && <EmployeesTab />}
      {tab === 'campaigns' && <CampaignsTab />}
    </div>
  )
}
