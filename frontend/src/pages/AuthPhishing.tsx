import { useEffect, useState, type ElementType } from 'react'
import {
  Users, ShieldAlert, Crosshair, Plus, Upload, RefreshCw,
  Mail, CheckCircle2, AlertTriangle, XCircle, ArrowRight,
  Play, Eye, Trash2, BarChart3, FileCode, Sparkles, Code2,
  Save, PenLine, Copy, Globe, GitFork, Lock,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { api, friendlyErrorMessage } from '../lib/api'
import { cn } from '../lib/utils'
import { useRole } from '../hooks/useRole'
import { Select } from '../components/ui/Select'
import { Modal } from '../components/Modal'

// ── Types ────────────────────────────────────────────────────────────────────

interface Employee {
  id: string
  email: string
  full_name: string | null
  department: string | null
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

interface PhishingTemplate {
  id: string
  name: string
  subject: string
  body_html: string
  is_public: boolean
  created_at: string
  updated_at: string
}

interface CommunityTemplate {
  id: string
  name: string
  subject: string
  body_html: string
  org_name: string
  org_id: string
  is_own: boolean
  created_at: string
}

interface Campaign {
  id: string
  name: string
  status: 'draft' | 'scheduled' | 'running' | 'completed' | 'cancelled'
  objective: 'click' | 'credentials' | 'report'
  context_asset_ids: string[]
  template_id: string | null
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
    employees: { email: string; full_name: string | null } | null
    email_sent_at: string | null
    link_clicked_at: string | null
    creds_entered_at: string | null
    reported_at: string | null
  }>
}

// ── Helpers ──────────────────────────────────────────────────────────────────

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
      await api.post<{ status: string; domain?: string }>('/hibp/check')
      setStatus({ msg: 'Queued — check will run in background', ok: true })
      load()
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    } finally {
      setCheckingHibp(false)
    }
  }

  const atRisk = employees.filter(e => (e.credential_breaches?.length || 0) > 0).length

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        <div className="glass rounded-lg p-4 border border-white/10">
          <p className="text-xs text-white/50 mb-1">Total employees</p>
          <p className="text-2xl font-bold text-horus-ivory">{employees.length}</p>
        </div>
        <div className="glass rounded-lg p-4 border border-white/10">
          <p className="text-xs text-white/50 mb-1">With exposed credentials</p>
          <p className={cn('text-2xl font-bold', atRisk > 0 ? 'text-red-400' : 'text-green-400')}>{atRisk}</p>
        </div>
      </div>

      <Link to="/credential-exposure" className="flex items-center gap-2 p-3 rounded-lg bg-blue-900/20 border border-blue-800/40 text-blue-300 hover:bg-blue-900/30 transition-colors">
        <ShieldAlert className="w-4 h-4 shrink-0" />
        <span className="text-sm">View all credential breaches in Credential Exposure</span>
        <ArrowRight className="w-3.5 h-3.5 ml-auto shrink-0" />
      </Link>

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

      <Modal open={showAdd} onClose={() => setShowAdd(false)} title="Add employee" className="max-w-lg">
        <div className="space-y-3">
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
      </Modal>

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

      {loading ? (
        <p className="text-sm text-white/40 py-8 text-center">Loading employees…</p>
      ) : employees.length === 0 ? (
        <div className="glass border border-white/10 rounded-lg py-12 text-center">
          <Users className="w-8 h-8 text-white/20 mx-auto mb-3" />
          <p className="text-sm text-white/40">No employees yet — add them or import a CSV</p>
        </div>
      ) : (
        <div className="glass border border-white/10 rounded-lg overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-white/10 text-white/40 text-xs">
                <th className="text-left px-4 py-3">Employee</th>
                <th className="text-left px-4 py-3">Department</th>
                <th className="text-center px-4 py-3">Credential breaches</th>
                <th className="text-left px-4 py-3">Last checked</th>
                {can('admin') && <th className="px-4 py-3" />}
              </tr>
            </thead>
            <tbody>
              {employees.map(emp => (
                <tr key={emp.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                  <td className="px-4 py-3">
                    <p className="text-white/90">{emp.full_name || emp.email}</p>
                    {emp.full_name && <p className="text-white/40 text-xs">{emp.email}</p>}
                  </td>
                  <td className="px-4 py-3 text-white/50">{emp.department || '—'}</td>
                  <td className="px-4 py-3 text-center">
                    {emp.credential_breaches?.length > 0 ? (
                      <span className="inline-flex items-center gap-1 text-red-400 font-medium">
                        <ShieldAlert className="w-4 h-4" />
                        {emp.credential_breaches.length}
                      </span>
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
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Tab: Templates ────────────────────────────────────────────────────────────

type EditorMode = 'manual' | 'ai'
type TemplateView = 'mine' | 'community'

function TemplatesTab() {
  const { can } = useRole()
  const [view, setView] = useState<TemplateView>('mine')
  const [templates, setTemplates] = useState<PhishingTemplate[]>([])
  const [community, setCommunity] = useState<CommunityTemplate[]>([])
  const [loading, setLoading] = useState(true)
  const [communityLoading, setCommunityLoading] = useState(false)
  const [status, setStatus] = useState<{ msg: string; ok: boolean } | null>(null)
  const [showEditor, setShowEditor] = useState(false)
  const [editorMode, setEditorMode] = useState<EditorMode>('manual')
  const [editing, setEditing] = useState<PhishingTemplate | null>(null)
  const [previewId, setPreviewId] = useState<string | null>(null)
  const [floatPreview, setFloatPreview] = useState<{ name: string; subject: string; body_html: string } | null>(null)
  const [forking, setForking] = useState<string | null>(null)

  // Manual form
  const [mName, setMName] = useState('')
  const [mSubject, setMSubject] = useState('')
  const [mBodyHtml, setMBodyHtml] = useState('')
  const [mIsPublic, setMIsPublic] = useState(false)

  // AI form
  const [aiName, setAiName] = useState('')
  const [aiObjective, setAiObjective] = useState<'click' | 'credentials' | 'report'>('click')
  const [aiScenario, setAiScenario] = useState('')
  const [aiIsPublic, setAiIsPublic] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [saving, setSaving] = useState(false)

  const load = () => {
    setLoading(true)
    api.get<PhishingTemplate[]>('/phishing/templates').then(setTemplates).finally(() => setLoading(false))
  }

  const loadCommunity = () => {
    setCommunityLoading(true)
    api.get<CommunityTemplate[]>('/phishing/templates/community').then(setCommunity).finally(() => setCommunityLoading(false))
  }

  useEffect(load, [])
  useEffect(() => { if (view === 'community') loadCommunity() }, [view])

  const openNew = () => {
    setEditing(null)
    setMName(''); setMSubject(''); setMBodyHtml(''); setMIsPublic(false)
    setAiName(''); setAiObjective('click'); setAiScenario(''); setAiIsPublic(false)
    setEditorMode('manual')
    setShowEditor(true)
  }

  const openEdit = (tpl: PhishingTemplate) => {
    setEditing(tpl)
    setMName(tpl.name); setMSubject(tpl.subject); setMBodyHtml(tpl.body_html); setMIsPublic(tpl.is_public)
    setEditorMode('manual')
    setShowEditor(true)
    setFloatPreview(null)
  }

  const saveManual = async () => {
    if (!mName || !mBodyHtml) return
    setSaving(true)
    setStatus(null)
    try {
      if (editing) {
        await api.patch(`/phishing/templates/${editing.id}`, { name: mName, subject: mSubject, body_html: mBodyHtml, is_public: mIsPublic })
        setStatus({ msg: 'Template updated', ok: true })
      } else {
        await api.post('/phishing/templates', { name: mName, subject: mSubject, body_html: mBodyHtml, is_public: mIsPublic })
        setStatus({ msg: 'Template saved', ok: true })
      }
      setShowEditor(false)
      load()
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    } finally {
      setSaving(false)
    }
  }

  const generateAi = async () => {
    if (!aiName || !aiScenario) return
    setGenerating(true)
    setStatus(null)
    try {
      const res = await api.post<PhishingTemplate & { pretext?: string }>('/phishing/templates/generate', {
        name: aiName, objective: aiObjective, scenario: aiScenario, is_public: aiIsPublic,
      })
      setStatus({ msg: `Generated: ${res.pretext || res.name}`, ok: true })
      setShowEditor(false)
      load()
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    } finally {
      setGenerating(false)
    }
  }

  const deleteTemplate = async (id: string) => {
    try {
      await api.delete(`/phishing/templates/${id}`)
      setPreviewId(null)
      load()
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    }
  }

  const forkTemplate = async (id: string) => {
    setForking(id)
    setStatus(null)
    try {
      await api.post(`/phishing/templates/${id}/fork`, {})
      setStatus({ msg: 'Template cloned to your library', ok: true })
      load()
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    } finally {
      setForking(null)
    }
  }

  const togglePublic = async (tpl: PhishingTemplate) => {
    try {
      await api.patch(`/phishing/templates/${tpl.id}`, { is_public: !tpl.is_public })
      load()
    } catch (e) {
      setStatus({ msg: friendlyErrorMessage(e), ok: false })
    }
  }

  const copyHtml = (html: string) => {
    navigator.clipboard.writeText(html).then(() => {
      setStatus({ msg: 'HTML copied to clipboard', ok: true })
      setTimeout(() => setStatus(null), 2000)
    })
  }

  return (
    <div className="space-y-4">
      {status && (
        <div className={cn('text-sm px-3 py-2 rounded border', status.ok ? 'bg-green-900/30 border-green-700/40 text-green-300' : 'bg-red-900/30 border-red-700/40 text-red-300')}>
          {status.msg}
        </div>
      )}

      {/* View switcher + action */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex gap-1 p-0.5 rounded-lg bg-white/5 border border-white/10">
          <button
            onClick={() => { setView('mine'); setShowEditor(false) }}
            className={cn('flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm transition-colors', view === 'mine' ? 'bg-white/10 text-white' : 'text-white/40 hover:text-white/70')}
          >
            <Lock className="w-3.5 h-3.5" /> My Templates
            <span className="ml-1 text-xs text-white/30">{templates.length}</span>
          </button>
          <button
            onClick={() => { setView('community'); setShowEditor(false) }}
            className={cn('flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm transition-colors', view === 'community' ? 'bg-white/10 text-white' : 'text-white/40 hover:text-white/70')}
          >
            <Globe className="w-3.5 h-3.5" /> Community
          </button>
        </div>
        {can('admin') && view === 'mine' && (
          <button onClick={openNew} className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-horus-lapis hover:bg-horus-lapis/80 text-sm text-white transition-colors shrink-0">
            <Plus className="w-4 h-4" /> New template
          </button>
        )}
      </div>

      {/* ── My Templates view ── */}
      {view === 'mine' && (
        <>
          {/* Editor panel */}
          <Modal open={showEditor} onClose={() => setShowEditor(false)} title={editing ? 'Edit template' : 'New template'} className="max-w-2xl">
            <div className="space-y-4">
              <div className="flex border-b border-white/10 -mx-6 px-6">
                <button
                  onClick={() => setEditorMode('manual')}
                  className={cn('flex items-center gap-2 px-4 py-3 text-sm transition-colors', editorMode === 'manual' ? 'bg-white/5 text-white border-b-2 border-horus-lapis' : 'text-white/50 hover:text-white/80')}
                >
                  <Code2 className="w-4 h-4" /> Manual editor
                </button>
                {!editing && (
                  <button
                    onClick={() => setEditorMode('ai')}
                    className={cn('flex items-center gap-2 px-4 py-3 text-sm transition-colors', editorMode === 'ai' ? 'bg-white/5 text-white border-b-2 border-horus-gold' : 'text-white/50 hover:text-white/80')}
                  >
                    <Sparkles className="w-4 h-4" /> Generate with AI
                  </button>
                )}
              </div>

              {editorMode === 'manual' ? (
                  <>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-xs text-white/50 mb-1 block">Template name</label>
                        <input value={mName} onChange={e => setMName(e.target.value)} placeholder="VPN session expired — IT"
                          className="w-full bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-lapis" />
                      </div>
                      <div>
                        <label className="text-xs text-white/50 mb-1 block">Email subject</label>
                        <input value={mSubject} onChange={e => setMSubject(e.target.value)} placeholder="[IT Security] Action required: verify your account"
                          className="w-full bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-lapis" />
                      </div>
                    </div>

                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <label className="text-xs text-white/50">HTML body</label>
                        <span className="text-xs text-white/25">{'{{employee_name}}'} {'{{tracking_url}}'} {'{{employee_email}}'}</span>
                      </div>
                      <textarea value={mBodyHtml} onChange={e => setMBodyHtml(e.target.value)} rows={16} spellCheck={false}
                        placeholder={'<html>\n<body>\n  <p>Hi {{employee_name}},</p>\n  <p>Your session has expired. Please verify your identity:</p>\n  <a href="{{tracking_url}}">Verify now</a>\n</body>\n</html>'}
                        className="w-full bg-black/40 border border-white/10 rounded px-3 py-2 text-sm text-green-300 placeholder:text-white/20 focus:outline-none focus:border-horus-lapis font-mono resize-y leading-relaxed" />
                    </div>

                    {/* Visibility toggle */}
                    <button
                      onClick={() => setMIsPublic(v => !v)}
                      className={cn('flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors w-full',
                        mIsPublic ? 'bg-green-900/20 border-green-700/40 text-green-300' : 'bg-white/5 border-white/10 text-white/50')}
                    >
                      {mIsPublic ? <Globe className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
                      <span className="flex-1 text-left">{mIsPublic ? 'Public — visible to the community' : 'Private — only your organisation'}</span>
                    </button>

                    <div className="flex gap-2">
                      <button onClick={saveManual} disabled={saving || !mName || !mBodyHtml}
                        className="flex items-center gap-2 px-4 py-1.5 rounded bg-horus-lapis text-white text-sm disabled:opacity-50 transition-colors hover:bg-horus-lapis/80">
                        <Save className="w-4 h-4" />
                        {saving ? 'Saving…' : editing ? 'Update template' : 'Save template'}
                      </button>
                      {mBodyHtml && (
                        <button onClick={() => setFloatPreview({ name: mName, subject: mSubject, body_html: mBodyHtml })}
                          className="flex items-center gap-2 px-3 py-1.5 rounded bg-white/10 text-white/60 text-sm transition-colors hover:bg-white/15">
                          <Eye className="w-4 h-4" /> Preview
                        </button>
                      )}
                    </div>
                  </>
                ) : (
                  <>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="text-xs text-white/50 mb-1 block">Template name</label>
                        <input value={aiName} onChange={e => setAiName(e.target.value)} placeholder="Corporate security alert"
                          className="w-full bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-gold" />
                      </div>
                      <div>
                        <label className="text-xs text-white/50 mb-1 block">Objective</label>
                        <Select
                          className="w-full"
                          value={aiObjective}
                          onValueChange={(v) => setAiObjective(v as typeof aiObjective)}
                          options={[
                            { value: 'click', label: 'Link click (urgency / curiosity)' },
                            { value: 'credentials', label: 'Credential harvest (fake login)' },
                            { value: 'report', label: 'Report test (suspicious email)' },
                          ]}
                        />
                      </div>
                    </div>

                    <div>
                      <label className="text-xs text-white/50 mb-1 block">Scenario</label>
                      <textarea value={aiScenario} onChange={e => setAiScenario(e.target.value)} rows={4}
                        placeholder="E.g.: IT alert about an expired VPN certificate requiring immediate renewal. The employee must click to renew within 24h or lose access."
                        className="w-full bg-white/5 border border-white/10 rounded px-3 py-2 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-gold resize-none" />
                    </div>

                    {/* Visibility toggle */}
                    <button
                      onClick={() => setAiIsPublic(v => !v)}
                      className={cn('flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors w-full',
                        aiIsPublic ? 'bg-green-900/20 border-green-700/40 text-green-300' : 'bg-white/5 border-white/10 text-white/50')}
                    >
                      {aiIsPublic ? <Globe className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
                      <span className="flex-1 text-left">{aiIsPublic ? 'Public — visible to the community' : 'Private — only your organisation'}</span>
                    </button>

                    <div className="flex items-center gap-3">
                      <button onClick={generateAi} disabled={generating || !aiName || !aiScenario}
                        className="flex items-center gap-2 px-4 py-1.5 rounded bg-horus-gold/20 border border-horus-gold/40 text-horus-gold text-sm disabled:opacity-50 transition-colors hover:bg-horus-gold/30">
                        <Sparkles className={cn('w-4 h-4', generating && 'animate-pulse')} />
                        {generating ? 'Generating…' : 'Generate & save'}
                      </button>
                      {generating && <p className="text-xs text-white/40">AI is generating your phishing template…</p>}
                    </div>
                  </>
                )}
            </div>
          </Modal>

          {/* My template list */}
          <p className="text-xs text-white/30">
            Placeholders: <code className="text-horus-gold">{'{{employee_name}}'}</code> · <code className="text-horus-gold">{'{{tracking_url}}'}</code> · <code className="text-horus-gold">{'{{employee_email}}'}</code>
          </p>

          {loading ? (
            <p className="text-sm text-white/40 py-8 text-center">Loading templates…</p>
          ) : templates.length === 0 ? (
            <div className="glass border border-white/10 rounded-lg py-12 text-center">
              <FileCode className="w-8 h-8 text-white/20 mx-auto mb-3" />
              <p className="text-sm text-white/40 mb-1">No templates yet</p>
              <p className="text-xs text-white/25">Create one manually or generate one with AI</p>
            </div>
          ) : (
            <div className="space-y-2">
              {templates.map(tpl => (
                <div key={tpl.id} className="glass border border-white/10 rounded-lg overflow-hidden">
                  <div className="flex items-center gap-3 px-4 py-3">
                    <FileCode className="w-4 h-4 text-horus-gold/60 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-white/90 font-medium truncate">{tpl.name}</p>
                        {tpl.is_public
                          ? <span className="flex items-center gap-1 text-xs text-green-400/80 bg-green-900/20 border border-green-700/30 px-1.5 py-0.5 rounded-full shrink-0"><Globe className="w-2.5 h-2.5" /> Public</span>
                          : <span className="flex items-center gap-1 text-xs text-white/30 bg-white/5 border border-white/10 px-1.5 py-0.5 rounded-full shrink-0"><Lock className="w-2.5 h-2.5" /> Private</span>
                        }
                      </div>
                      {tpl.subject && <p className="text-xs text-white/40 truncate mt-0.5">Subject: {tpl.subject}</p>}
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <button onClick={() => setPreviewId(previewId === tpl.id ? null : tpl.id)}
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-white/50 hover:text-white text-xs transition-colors">
                        <Eye className="w-3.5 h-3.5" /> Preview
                      </button>
                      {can('admin') && (
                        <>
                          <button onClick={() => togglePublic(tpl)}
                            className={cn('flex items-center gap-1.5 px-2.5 py-1 rounded text-xs transition-colors',
                              tpl.is_public ? 'bg-green-900/20 hover:bg-red-900/20 text-green-400 hover:text-red-400 border border-green-700/30 hover:border-red-700/30'
                                : 'bg-white/5 hover:bg-green-900/20 text-white/40 hover:text-green-400 border border-white/10 hover:border-green-700/30')}
                            title={tpl.is_public ? 'Make private' : 'Make public'}>
                            {tpl.is_public ? <Lock className="w-3.5 h-3.5" /> : <Globe className="w-3.5 h-3.5" />}
                            {tpl.is_public ? 'Make private' : 'Make public'}
                          </button>
                          <button onClick={() => openEdit(tpl)}
                            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-white/50 hover:text-white text-xs transition-colors">
                            <PenLine className="w-3.5 h-3.5" /> Edit
                          </button>
                          <button onClick={() => copyHtml(tpl.body_html)}
                            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-white/50 hover:text-white text-xs transition-colors">
                            <Copy className="w-3.5 h-3.5" /> HTML
                          </button>
                          <button onClick={() => deleteTemplate(tpl.id)}
                            className="p-1.5 rounded text-white/20 hover:text-red-400 hover:bg-red-900/20 transition-colors">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </>
                      )}
                    </div>
                  </div>

                  {previewId === tpl.id && (
                    <div className="border-t border-white/10">
                      <div className="px-4 py-2 bg-black/20 flex items-center justify-between">
                        <span className="text-xs text-white/40">Email preview</span>
                        <span className="text-xs text-white/25">Placeholders will be replaced when the campaign is launched</span>
                      </div>
                      <div className="bg-white rounded-b-lg overflow-hidden">
                        <iframe srcDoc={tpl.body_html || '<p style="padding:1rem;color:#666">No HTML content</p>'}
                          title={`Preview: ${tpl.name}`} className="w-full" style={{ height: '380px', border: 'none' }} sandbox="allow-same-origin" />
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {/* ── Community view ── */}
      {view === 'community' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-xs text-white/40">
              Browse templates shared by the community. Clone any to your library to use in campaigns.
            </p>
            <button onClick={loadCommunity} className="flex items-center gap-1.5 text-xs text-white/30 hover:text-white/60 transition-colors">
              <RefreshCw className="w-3 h-3" /> Refresh
            </button>
          </div>

          {communityLoading ? (
            <p className="text-sm text-white/40 py-8 text-center">Loading community templates…</p>
          ) : community.length === 0 ? (
            <div className="glass border border-white/10 rounded-lg py-12 text-center">
              <Globe className="w-8 h-8 text-white/20 mx-auto mb-3" />
              <p className="text-sm text-white/40 mb-1">No public templates yet</p>
              <p className="text-xs text-white/25">Be the first — make one of your templates public</p>
            </div>
          ) : (
            <div className="space-y-2">
              {community.map(tpl => (
                <div key={tpl.id} className="glass border border-white/10 rounded-lg overflow-hidden">
                  <div className="flex items-center gap-3 px-4 py-3">
                    <Globe className="w-4 h-4 text-green-400/50 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-white/90 font-medium truncate">{tpl.name}</p>
                        <span className="text-xs text-white/30 bg-white/5 border border-white/10 px-1.5 py-0.5 rounded-full shrink-0">{tpl.org_name}</span>
                        {tpl.is_own && <span className="text-xs text-horus-gold/70 bg-horus-gold/10 border border-horus-gold/20 px-1.5 py-0.5 rounded-full shrink-0">yours</span>}
                      </div>
                      {tpl.subject && <p className="text-xs text-white/40 truncate mt-0.5">Subject: {tpl.subject}</p>}
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      <button onClick={() => setPreviewId(previewId === tpl.id ? null : tpl.id)}
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-white/5 hover:bg-white/10 text-white/50 hover:text-white text-xs transition-colors">
                        <Eye className="w-3.5 h-3.5" /> Preview
                      </button>
                      {can('admin') && !tpl.is_own && (
                        <button onClick={() => forkTemplate(tpl.id)} disabled={forking === tpl.id}
                          className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-horus-lapis/20 hover:bg-horus-lapis/40 border border-horus-lapis/30 text-horus-lapis text-xs transition-colors disabled:opacity-50">
                          <GitFork className="w-3.5 h-3.5" />
                          {forking === tpl.id ? 'Cloning…' : 'Clone to my library'}
                        </button>
                      )}
                    </div>
                  </div>

                  {previewId === tpl.id && (
                    <div className="border-t border-white/10">
                      <div className="px-4 py-2 bg-black/20">
                        <span className="text-xs text-white/40">Email preview</span>
                      </div>
                      <div className="bg-white rounded-b-lg overflow-hidden">
                        <iframe srcDoc={tpl.body_html || '<p style="padding:1rem;color:#666">No HTML content</p>'}
                          title={`Preview: ${tpl.name}`} className="w-full" style={{ height: '380px', border: 'none' }} sandbox="allow-same-origin" />
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Floating preview from manual editor */}
      {floatPreview && (
        <div className="fixed inset-y-0 left-60 right-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="glass border border-white/10 rounded-xl w-full max-w-2xl max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-white/10 shrink-0">
              <h2 className="font-semibold text-white text-sm">{floatPreview.name || 'Preview'}</h2>
              <button onClick={() => setFloatPreview(null)} className="text-white/40 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>
            {floatPreview.subject && (
              <p className="px-4 py-2 text-xs text-white/50 border-b border-white/10 shrink-0">Subject: {floatPreview.subject}</p>
            )}
            <div className="bg-white rounded-b-xl flex-1 overflow-hidden">
              <iframe srcDoc={floatPreview.body_html} title="Preview" className="w-full h-full"
                style={{ border: 'none', minHeight: '480px' }} sandbox="allow-same-origin" />
            </div>
          </div>
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
  const [templates, setTemplates] = useState<PhishingTemplate[]>([])
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
  const [templateId, setTemplateId] = useState<string>('')

  const load = () => {
    setLoading(true)
    Promise.all([
      api.get<Campaign[]>('/phishing/campaigns'),
      api.get<Asset[]>('/assets'),
      api.get<Employee[]>('/phishing/employees'),
      api.get<PhishingTemplate[]>('/phishing/templates'),
    ]).then(([c, a, e, t]) => {
      setCampaigns(c)
      setAssets(a)
      setEmployees(e)
      setTemplates(t)
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
        template_id: templateId || null,
      })
      setName(''); setObjective('click'); setSelectedAssets([]); setScheduleCron(''); setTemplateId('')
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

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="New phishing campaign" className="max-w-2xl">
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-white/50 mb-1 block">Campaign name</label>
              <input value={name} onChange={e => setName(e.target.value)} placeholder="Q3 VPN awareness" className="w-full bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-lapis" />
            </div>
            <div>
              <label className="text-xs text-white/50 mb-1 block">Objective</label>
              <Select
                className="w-full"
                value={objective}
                onValueChange={(v) => setObjective(v as typeof objective)}
                options={[
                  { value: 'click', label: 'Link click (click-through rate)' },
                  { value: 'credentials', label: 'Credential harvest (login test)' },
                  { value: 'report', label: 'Report test (awareness check)' },
                ]}
              />
            </div>
          </div>

          <div>
            <label className="text-xs text-white/50 mb-1 block">
              Email template <span className="text-white/25">(optional — AI-generated if not selected)</span>
            </label>
            <Select
              className="w-full"
              value={templateId}
              onValueChange={setTemplateId}
              options={[
                { value: '', label: '— Generate with AI (using asset context)' },
                ...templates.map(t => ({ value: t.id, label: t.name })),
              ]}
            />
          </div>

          {!templateId && (
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
          )}

          <div>
            <label className="text-xs text-white/50 mb-1 block">Schedule (cron, optional — leave empty for manual launch)</label>
            <input value={scheduleCron} onChange={e => setScheduleCron(e.target.value)} placeholder="0 9 * * 1  (every Monday at 9:00)" className="w-full bg-white/5 border border-white/10 rounded px-3 py-1.5 text-sm text-white placeholder:text-white/30 focus:outline-none focus:border-horus-lapis font-mono" />
          </div>

          <div className="flex gap-2">
            <button onClick={createCampaign} className="px-3 py-1.5 rounded bg-horus-lapis text-white text-sm">Create</button>
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 rounded bg-white/10 text-white/60 text-sm">Cancel</button>
          </div>
        </div>
      </Modal>

      {loading ? (
        <p className="text-sm text-white/40 py-8 text-center">Loading campaigns…</p>
      ) : campaigns.length === 0 ? (
        <div className="glass border border-white/10 rounded-lg py-12 text-center">
          <Crosshair className="w-8 h-8 text-white/20 mx-auto mb-3" />
          <p className="text-sm text-white/40">No campaigns yet — create one to start training your team</p>
        </div>
      ) : (
        <div className="space-y-2">
          {campaigns.map(c => {
            const tplName = c.template_id ? templates.find(t => t.id === c.template_id)?.name : null
            return (
              <div key={c.id} className="glass border border-white/10 rounded-lg p-4 flex items-center gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <p className="text-white/90 font-medium truncate">{c.name}</p>
                    {statusBadge(c.status)}
                  </div>
                  <p className="text-xs text-white/40">
                    {objectiveLabel(c.objective)}
                    {tplName ? ` · Template: ${tplName}` : ` · ${c.context_asset_ids.length} assets en contexto`}
                    {' · '}Created {new Date(c.created_at).toLocaleDateString()}
                  </p>
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
            )
          })}
        </div>
      )}

      {viewResults && (
        <div className="fixed inset-y-0 left-60 right-0 bg-black/60 flex items-center justify-center z-50 p-4">
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
              <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-white/30 border-b border-white/10">
                    <th className="text-left py-2">Employee</th>
                    <th className="text-center py-2">Sent</th>
                    <th className="text-center py-2">Clicked</th>
                    <th className="text-center py-2">Creds</th>
                    <th className="text-center py-2">Reported</th>
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
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

type Tab = 'employees' | 'templates' | 'campaigns'

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
          { id: 'templates', label: 'Templates', icon: FileCode },
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
      {tab === 'templates' && <TemplatesTab />}
      {tab === 'campaigns' && <CampaignsTab />}
    </div>
  )
}
