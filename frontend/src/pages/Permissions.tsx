import { useEffect, useState } from 'react'
import { Plus, Trash2, ChevronRight } from 'lucide-react'
import { api } from '../lib/api'
import { cn, modeBadgeColor } from '../lib/utils'

interface Policy {
  id: string
  name: string
  description: string | null
  scope: string
  scope_value: string | null
  rules: Rule[]
  is_active: boolean
}

interface Rule {
  name?: string
  action: string
  mode: string
  conditions?: {
    asset_tags?: string[]
    is_internal_only?: boolean
    severity_max?: string
  }
}

const MODES = ['suggest_only', 'approval_required', 'auto']
const ACTIONS = [
  'update_library', 'apply_firewall_rule', 'restart_service',
  'block_ip', 'patch_config', 'disable_feature', 'rotate_credentials', '*',
]

const MODE_LABEL: Record<string, string> = {
  auto: 'AUTO',
  approval_required: 'APPROVAL REQUIRED',
  suggest_only: 'SUGGEST ONLY',
}

export default function Permissions() {
  const [policies, setPolicies] = useState<Policy[]>([])
  const [selected, setSelected] = useState<Policy | null>(null)
  const [adding, setAdding] = useState(false)
  const [newName, setNewName] = useState('')
  const [newRules, setNewRules] = useState<Rule[]>([{ action: 'update_library', mode: 'suggest_only' }])

  const load = () => api.get<Policy[]>('/permissions').then(setPolicies)
  useEffect(() => { load() }, [])

  const createPolicy = async () => {
    await api.post('/permissions', { name: newName, scope: 'org', rules: newRules })
    setAdding(false)
    setNewName('')
    load()
  }

  const deletePolicy = async (id: string) => {
    await api.delete(`/permissions/${id}`)
    if (selected?.id === id) setSelected(null)
    load()
  }

  const addRule = () => setNewRules([...newRules, { action: 'update_library', mode: 'suggest_only' }])
  const updateRule = (i: number, patch: Partial<Rule>) =>
    setNewRules(newRules.map((r, j) => (j === i ? { ...r, ...patch } : r)))

  const field = 'bg-bg border border-border rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-accent'

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Permission Policies</h1>
        <button
          onClick={() => setAdding(true)}
          className="flex items-center gap-2 bg-accent text-bg text-sm px-4 py-2 rounded hover:bg-accent/90 transition-colors"
        >
          <Plus className="w-4 h-4" /> New Policy
        </button>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Left: policy list */}
        <div className="space-y-2">
          {policies.map((p) => (
            <button
              key={p.id}
              onClick={() => setSelected(p)}
              className={cn(
                'w-full text-left bg-surface border rounded-lg p-3 transition-colors',
                selected?.id === p.id ? 'border-accent' : 'border-border hover:border-accent/40',
              )}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-white">{p.name}</span>
                <ChevronRight className="w-3.5 h-3.5 text-muted" />
              </div>
              <p className="text-xs text-muted mt-0.5 capitalize">{p.scope}{p.scope_value ? `: ${p.scope_value}` : ''}</p>
              <p className="text-xs text-muted mt-0.5">{p.rules.length} rules</p>
            </button>
          ))}
          {policies.length === 0 && <p className="text-xs text-muted">No policies yet.</p>}
        </div>

        {/* Right: detail or editor */}
        <div className="col-span-2">
          {adding && (
            <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
              <h2 className="text-sm font-medium">New Policy</h2>
              <div>
                <label className="text-xs text-muted mb-1 block">Policy name</label>
                <input className={`${field} w-full`} value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="e.g. Internal asset automation" />
              </div>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-xs text-muted uppercase">Rules</p>
                  <button onClick={addRule} className="text-xs text-accent hover:underline">+ Add rule</button>
                </div>
                {newRules.map((rule, i) => (
                  <div key={i} className="grid grid-cols-2 gap-3 p-3 bg-bg rounded border border-border">
                    <div>
                      <label className="text-xs text-muted mb-1 block">Action</label>
                      <select className={`${field} w-full`} value={rule.action} onChange={(e) => updateRule(i, { action: e.target.value })}>
                        {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="text-xs text-muted mb-1 block">Mode</label>
                      <select className={`${field} w-full`} value={rule.mode} onChange={(e) => updateRule(i, { mode: e.target.value })}>
                        {MODES.map((m) => <option key={m} value={m}>{MODE_LABEL[m]}</option>)}
                      </select>
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex justify-end gap-3">
                <button onClick={() => setAdding(false)} className="text-sm text-muted hover:text-white transition-colors">Cancel</button>
                <button onClick={createPolicy} className="text-sm bg-accent text-bg px-4 py-1.5 rounded hover:bg-accent/90 transition-colors">Save</button>
              </div>
            </div>
          )}

          {selected && !adding && (
            <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
              <div className="flex items-start justify-between">
                <div>
                  <h2 className="text-sm font-medium text-white">{selected.name}</h2>
                  <p className="text-xs text-muted mt-0.5 capitalize">Scope: {selected.scope}{selected.scope_value ? ` → ${selected.scope_value}` : ''}</p>
                </div>
                <button onClick={() => deletePolicy(selected.id)} className="text-muted hover:text-severity-critical transition-colors">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-2">
                {selected.rules.map((rule, i) => (
                  <div key={i} className="flex items-center justify-between p-3 bg-bg rounded border border-border">
                    <div>
                      <span className="text-sm text-white font-mono">{rule.action}</span>
                      {rule.conditions?.asset_tags && (
                        <span className="text-xs text-muted ml-2">tags: {rule.conditions.asset_tags.join(', ')}</span>
                      )}
                      {rule.conditions?.is_internal_only && (
                        <span className="text-xs text-muted ml-2">internal only</span>
                      )}
                    </div>
                    <span className={cn('text-xs px-2 py-0.5 rounded border font-mono', modeBadgeColor(rule.mode))}>
                      {MODE_LABEL[rule.mode] ?? rule.mode}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
