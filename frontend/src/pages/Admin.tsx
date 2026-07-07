import { useEffect, useState } from 'react'
import { api, ApiError } from '../lib/api'
import { Select } from '../components/ui/Select'

// Horus super-admin panel — create customer orgs manually (enterprise / Custom plan).
// Access is enforced by the backend (SUPERADMIN_EMAILS allowlist); a non-superadmin
// just gets 403 here. There's deliberately no nav link: it's an internal ops tool.

interface Org {
  id: string
  name: string
  members: number
  settings: { plan?: string; source?: string } | null
  created_at: string
}

interface ProvisionResult {
  org_id: string
  email: string
  temp_password: string | null
  emailed: boolean
}

export default function Admin() {
  const [orgs, setOrgs] = useState<Org[]>([])
  const [forbidden, setForbidden] = useState(false)
  const [loading, setLoading] = useState(true)
  const [orgName, setOrgName] = useState('')
  const [adminEmail, setAdminEmail] = useState('')
  const [plan, setPlan] = useState('custom')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [created, setCreated] = useState<ProvisionResult | null>(null)

  async function load() {
    try {
      const res = await api.get<{ orgs: Org[] }>('/admin/orgs', 0)
      setOrgs(res.orgs)
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) setForbidden(true)
      else setError(e instanceof Error ? e.message : 'Failed to load')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void load() }, [])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    setCreated(null)
    try {
      const res = await api.post<ProvisionResult>('/admin/orgs', {
        org_name: orgName, admin_email: adminEmail, plan,
      })
      setCreated(res)
      setOrgName('')
      setAdminEmail('')
      await load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create organization')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) {
    return <div className="min-h-screen bg-bg flex items-center justify-center text-muted text-sm">Loading…</div>
  }
  if (forbidden) {
    return (
      <div className="min-h-screen bg-bg flex items-center justify-center p-4">
        <div className="bg-surface border border-border rounded-xl p-6 text-center text-sm text-gray-400 max-w-sm">
          Not authorized. This panel is restricted to Horus super-admins.
        </div>
      </div>
    )
  }

  const inputClass = 'w-full rounded-lg bg-bg border border-border px-3 py-2 text-sm text-white placeholder:text-muted focus:border-accent outline-none'

  return (
    <div className="min-h-screen bg-bg p-6">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-2xl font-semibold text-white mb-1">Horus admin</h1>
        <p className="text-sm text-muted mb-6">Provision a customer organization and its first admin user.</p>

        <form onSubmit={submit} className="bg-surface border border-border rounded-xl p-5 mb-8 grid gap-4 sm:grid-cols-4 items-end">
          <label className="block sm:col-span-2">
            <span className="text-xs text-muted block mb-1">Organization name</span>
            <input className={inputClass} value={orgName} onChange={e => setOrgName(e.target.value)} required maxLength={100} placeholder="Acme Corp" />
          </label>
          <label className="block sm:col-span-2">
            <span className="text-xs text-muted block mb-1">Admin email</span>
            <input className={inputClass} type="email" value={adminEmail} onChange={e => setAdminEmail(e.target.value)} required placeholder="ciso@acme.com" />
          </label>
          <label className="block">
            <span className="text-xs text-muted block mb-1">Plan</span>
            <Select
              className="w-full"
              value={plan}
              onValueChange={setPlan}
              options={[
                { value: 'custom', label: 'Custom' },
                { value: 'pro', label: 'Pro' },
              ]}
            />
          </label>
          <button type="submit" disabled={submitting} className="sm:col-start-4 rounded-lg bg-accent text-black font-medium px-4 py-2 text-sm disabled:opacity-50">
            {submitting ? 'Creating…' : 'Create organization'}
          </button>
        </form>

        {error && <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">{error}</div>}
        {created && (
          <div className="mb-6 rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-3 text-sm text-green-100">
            <div className="font-medium mb-1">Organization created.</div>
            <div>Admin: {created.email}</div>
            {created.temp_password
              ? <div>Temporary password: <code className="text-white">{created.temp_password}</code> {created.emailed ? '(also emailed)' : '(email failed — relay this manually)'}</div>
              : <div>Linked to an existing account; they sign in with their current password.</div>}
          </div>
        )}

        <h2 className="text-sm font-semibold text-white mb-2">Organizations ({orgs.length})</h2>
        <div className="bg-surface border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted border-b border-border">
                <th className="px-4 py-2 font-medium">Name</th>
                <th className="px-4 py-2 font-medium">Plan</th>
                <th className="px-4 py-2 font-medium">Source</th>
                <th className="px-4 py-2 font-medium">Members</th>
                <th className="px-4 py-2 font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {orgs.map(o => (
                <tr key={o.id} className="border-b border-border/50 last:border-0 text-gray-200">
                  <td className="px-4 py-2">{o.name}</td>
                  <td className="px-4 py-2">{o.settings?.plan ?? '—'}</td>
                  <td className="px-4 py-2">{o.settings?.source ?? '—'}</td>
                  <td className="px-4 py-2">{o.members}</td>
                  <td className="px-4 py-2 text-muted">{new Date(o.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
              {orgs.length === 0 && <tr><td colSpan={5} className="px-4 py-6 text-center text-muted">No organizations yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
