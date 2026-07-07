import { useEffect, useState } from 'react'
import { UserPlus, Trash2, Eye, Wrench, Crown, KeyRound } from 'lucide-react'
import { api } from '../lib/api'
import { useRole, type Role } from '../hooks/useRole'
import { cn } from '../lib/utils'
import { Select } from '../components/ui/Select'
import { useConfirm } from '../components/ui/ConfirmProvider'
import { Modal } from '../components/Modal'

interface Member {
  id: string
  email: string | null
  full_name: string | null
  role: Role
  created_at: string
  pending?: false
}

interface PendingInvite {
  id: string
  email: string
  role: Role
  expires_at: string
  pending: true
}

const ROLE_META: Record<Role, { label: string; icon: React.ElementType; color: string; perms: string[] }> = {
  admin: {
    label: 'Admin',
    icon: Crown,
    color: 'text-severity-critical',
    perms: ['Manage team members', 'Create / delete assets', 'Trigger scans', 'Approve AI suggestions', 'Configure AI permissions', 'View everything'],
  },
  analyst: {
    label: 'Analyst',
    icon: Wrench,
    color: 'text-accent',
    perms: ['Create / edit assets', 'Trigger scans', 'Approve AI suggestions', 'View findings', 'View dashboard'],
  },
  viewer: {
    label: 'Viewer',
    icon: Eye,
    color: 'text-muted',
    perms: ['View dashboard', 'View assets', 'View findings', 'View scans'],
  },
}

const roleOptions = (Object.keys(ROLE_META) as Role[]).map((r) => ({ value: r, label: ROLE_META[r].label }))

export default function Team() {
  const { role: myRole, can } = useRole()
  const confirm = useConfirm()
  const [members, setMembers] = useState<Member[]>([])
  const [loading, setLoading] = useState(true)
  const [showInvite, setShowInvite] = useState(false)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState<Role>('analyst')
  const [inviteResult, setInviteResult] = useState<{ temp_password?: string; email?: string } | null>(null)
  const [resetResult, setResetResult] = useState<{ temp_password: string; email: string | null } | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    setLoading(true)
    const data = await api.get<{ members: Member[]; pending: PendingInvite[] }>('/team')
    setMembers(data.members)
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  const invite = async () => {
    setError(null)
    try {
      const result = await api.post<{ temp_password: string; email: string }>(
        '/team/invite', { email: inviteEmail, role: inviteRole }
      )
      setInviteResult(result)
      setInviteEmail('')
      load()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to invite user')
    }
  }

  const changeRole = async (userId: string, newRole: Role) => {
    await api.patch(`/team/${userId}/role`, { role: newRole })
    load()
  }

  const resetPassword = async (member: Member) => {
    if (!(await confirm(`Reset the password for ${member.email || member.full_name}? They will get a temporary password and must change it on next login.`))) return
    const result = await api.post<{ temp_password: string }>(`/team/${member.id}/reset-password`, {})
    setResetResult({ temp_password: result.temp_password, email: member.email })
  }

  const removeMember = async (userId: string) => {
    if (!(await confirm({ message: 'Remove this member from the team?', danger: true, confirmLabel: 'Remove' }))) return
    await api.delete(`/team/${userId}`)
    load()
  }

  const field = 'bg-bg border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-accent'

  return (
    <div className="space-y-8">
      <Modal open={resetResult !== null} onClose={() => setResetResult(null)} title="Password reset" className="max-w-md">
        <div className="space-y-3">
          <p className="text-sm text-mode-auto">New temporary password for <strong>{resetResult?.email}</strong>:</p>
          <div className="bg-bg border border-border rounded p-3">
            <p className="text-xs text-muted mb-1">Share securely:</p>
            <p className="font-mono text-sm text-white select-all">{resetResult?.temp_password}</p>
          </div>
          <p className="text-xs text-muted">The user must change this password on next login. Their existing sessions have been signed out.</p>
          <div className="flex justify-end">
            <button onClick={() => setResetResult(null)} className="text-sm text-accent hover:underline">Close</button>
          </div>
        </div>
      </Modal>

      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">Team</h1>
        {can('admin') && (
          <button
            onClick={() => { setShowInvite(true); setInviteResult(null) }}
            className="flex items-center gap-2 bg-accent text-bg text-sm px-4 py-2 rounded hover:bg-accent/90 transition-colors"
          >
            <UserPlus className="w-4 h-4" /> Invite member
          </button>
        )}
      </div>

      <Modal open={showInvite} onClose={() => setShowInvite(false)} title="New member" className="max-w-lg">
        <div className="space-y-4">
          {inviteResult ? (
            <div className="space-y-3">
              <p className="text-sm text-mode-auto">User <strong>{inviteResult.email}</strong> added successfully.</p>
              {inviteResult.temp_password ? (
                <>
                  <div className="bg-bg border border-border rounded p-3">
                    <p className="text-xs text-muted mb-1">Temporary password (share securely):</p>
                    <p className="font-mono text-sm text-white select-all">{inviteResult.temp_password}</p>
                  </div>
                  <p className="text-xs text-muted">The user should change this password on first login.</p>
                </>
              ) : (
                <p className="text-xs text-muted">This account already existed and keeps its current password.</p>
              )}
              <button onClick={() => setShowInvite(false)} className="text-sm text-accent hover:underline">Close</button>
            </div>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-muted mb-1 block">Email</label>
                  <input
                    className={`${field} w-full`}
                    type="email"
                    value={inviteEmail}
                    onChange={(e) => setInviteEmail(e.target.value)}
                    placeholder="user@company.com"
                  />
                </div>
                <div>
                  <label className="text-xs text-muted mb-1 block">Role</label>
                  <Select
                    className="w-full"
                    value={inviteRole}
                    onValueChange={(v) => setInviteRole(v as Role)}
                    options={roleOptions}
                  />
                </div>
              </div>
              {error && <p className="text-xs text-severity-critical">{error}</p>}
              <div className="flex justify-end gap-3">
                <button onClick={() => setShowInvite(false)} className="text-sm text-muted hover:text-white transition-colors">Cancel</button>
                <button
                  onClick={invite}
                  disabled={!inviteEmail}
                  className="text-sm bg-accent text-bg px-4 py-1.5 rounded hover:bg-accent/90 transition-colors disabled:opacity-50"
                >
                  Create user
                </button>
              </div>
            </>
          )}
        </div>
      </Modal>

      <div className="bg-surface border border-border rounded-lg overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-xs text-muted">
              <th className="text-left py-3 px-4 font-medium">User</th>
              <th className="text-left py-3 px-4 font-medium">Role</th>
              <th className="text-left py-3 px-4 font-medium">Member since</th>
              {can('admin') && <th className="py-3 px-4" />}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={4} className="py-8 text-center text-muted text-xs">Loading…</td></tr>
            ) : (
              members.map((m) => {
                const meta = ROLE_META[m.role]
                const Icon = meta.icon
                return (
                  <tr key={m.id} className="border-b border-border hover:bg-white/[0.02] transition-colors">
                    <td className="py-3 px-4">
                      <p className="font-medium text-white">{m.full_name || m.email}</p>
                      {m.full_name && <p className="text-xs text-muted">{m.email}</p>}
                    </td>
                    <td className="py-3 px-4">
                      {can('admin') ? (
                        <Select
                          value={m.role}
                          onValueChange={(v) => changeRole(m.id, v as Role)}
                          options={roleOptions}
                          className="py-1 text-xs"
                        />
                      ) : (
                        <span className={cn('flex items-center gap-1.5 text-xs', meta.color)}>
                          <Icon className="w-3.5 h-3.5" />
                          {meta.label}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-xs text-muted">
                      {new Date(m.created_at).toLocaleDateString()}
                    </td>
                    {can('admin') && (
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-3">
                          <button
                            onClick={() => resetPassword(m)}
                            className="text-muted hover:text-accent transition-colors"
                            title="Reset password"
                          >
                            <KeyRound className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => removeMember(m.id)}
                            className="text-muted hover:text-severity-critical transition-colors"
                            title="Remove from team"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      <div>
        <h2 className="text-sm font-medium text-muted uppercase mb-4">Role permissions</h2>
        <div className="grid grid-cols-3 gap-4">
          {(Object.entries(ROLE_META) as [Role, typeof ROLE_META[Role]][]).map(([role, meta]) => {
            const Icon = meta.icon
            return (
              <div key={role} className={cn('bg-surface border rounded-lg p-4', myRole === role ? 'border-accent/50' : 'border-border')}>
                <div className={cn('flex items-center gap-2 mb-3', meta.color)}>
                  <Icon className="w-4 h-4" />
                  <span className="text-sm font-medium">{meta.label}</span>
                  {myRole === role && <span className="text-xs text-muted ml-auto">(your role)</span>}
                </div>
                <ul className="space-y-1.5">
                  {meta.perms.map((p) => (
                    <li key={p} className="text-xs text-white/70 flex items-center gap-1.5">
                      <span className="w-1 h-1 rounded-full bg-current shrink-0" />
                      {p}
                    </li>
                  ))}
                </ul>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
