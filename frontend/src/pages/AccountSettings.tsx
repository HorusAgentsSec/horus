import { useEffect, useState } from 'react'
import { LogOut, ShieldCheck } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { cn } from '../lib/utils'
import { useUser } from '../contexts/UserContext'
import { useConfirm } from '../components/ui/ConfirmProvider'

const field =
  'bg-bg border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-accent w-full'

function ProfileSection() {
  const { refreshProfile } = useUser()
  const [profile, setProfile] = useState<{ full_name: string; email: string; role: string } | null>(null)
  const [name, setName] = useState('')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .get<{ full_name: string | null; email: string; role: string }>('/account/profile')
      .then((p) => {
        setProfile({ full_name: p.full_name ?? '', email: p.email, role: p.role })
        setName(p.full_name ?? '')
      })
      .catch((e) => setError(friendlyErrorMessage(e)))
  }, [])

  const dirty = profile !== null && name.trim() !== profile.full_name.trim()

  const save = async () => {
    setSaving(true)
    setError(null)
    try {
      await api.put('/account/profile', { full_name: name })
      setProfile((p) => (p ? { ...p, full_name: name.trim() } : p))
      await refreshProfile()
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Failed to save profile'))
    } finally {
      setSaving(false)
    }
  }

  if (!profile) {
    return (
      <section className="bg-surface border border-border rounded-lg p-6">
        <p className="text-xs text-muted">{error ?? 'Loading…'}</p>
      </section>
    )
  }

  return (
    <section className="bg-surface border border-border rounded-lg p-6 space-y-4">
      <h2 className="text-sm font-medium text-white">Profile</h2>

      <div>
        <label htmlFor="acct-name" className="text-xs text-muted mb-1 block">
          Name
        </label>
        <input
          id="acct-name"
          className={field}
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Your name"
        />
      </div>

      <div>
        <label htmlFor="acct-email" className="text-xs text-muted mb-1 block">
          Email
        </label>
        <input
          id="acct-email"
          className={cn(field, 'text-muted cursor-not-allowed')}
          value={profile.email}
          readOnly
        />
      </div>

      <div>
        <label htmlFor="acct-role" className="text-xs text-muted mb-1 block">
          Role
        </label>
        <input
          id="acct-role"
          className={cn(field, 'text-muted cursor-not-allowed capitalize')}
          value={profile.role}
          readOnly
        />
        <p className="text-[11px] text-muted mt-1">
          Your role is managed by an organization admin from the Team page.
        </p>
      </div>

      {error && <p className="text-xs text-severity-critical">{error}</p>}
      <button
        onClick={save}
        disabled={saving || !dirty}
        className="text-sm bg-accent text-bg px-4 py-1.5 rounded hover:bg-accent/90 transition-colors disabled:opacity-50"
      >
        {saving ? 'Saving…' : saved ? 'Saved ✓' : 'Save'}
      </button>
    </section>
  )
}

function SessionsSection() {
  const confirm = useConfirm()
  const { signOut } = useUser()
  const [working, setWorking] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const logoutOthers = async () => {
    const ok = await confirm({
      title: 'Sign out other sessions?',
      message:
        'This signs you out everywhere except this device. Any other browser or device using your account will need to log in again.',
      confirmLabel: 'Sign out other sessions',
    })
    if (!ok) return
    setWorking(true)
    setError(null)
    try {
      await api.post('/account/logout-others')
      setDone(true)
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Failed to sign out other sessions'))
    } finally {
      setWorking(false)
    }
  }

  return (
    <section className="bg-surface border border-border rounded-lg p-6 space-y-4">
      <h2 className="text-sm font-medium text-white">Active sessions</h2>
      <p className="text-xs text-muted leading-relaxed">
        If you signed in on a shared or lost device, sign out everywhere else. This keeps your
        current session and revokes all the others immediately.
      </p>
      {done ? (
        <p className="flex items-center gap-2 text-sm text-mode-auto">
          <ShieldCheck className="w-4 h-4" /> Other sessions signed out.
        </p>
      ) : (
        <>
          {error && <p className="text-xs text-severity-critical">{error}</p>}
          <button
            onClick={logoutOthers}
            disabled={working}
            className="inline-flex items-center gap-2 text-sm border border-border text-white px-4 py-1.5 rounded hover:bg-bg transition-colors disabled:opacity-50"
          >
            <LogOut className="w-4 h-4" />
            {working ? 'Signing out…' : 'Sign out all other sessions'}
          </button>
        </>
      )}

      <div className="border-t border-border pt-4">
        <p className="text-xs text-muted mb-3">Sign out of this device.</p>
        <button
          onClick={signOut}
          className="inline-flex items-center gap-2 text-sm bg-accent text-bg px-4 py-1.5 rounded hover:bg-accent/90 transition-colors"
        >
          <LogOut className="w-4 h-4" />
          Sign out
        </button>
      </div>
    </section>
  )
}

const TABS = [
  { id: 'profile', label: 'Profile' },
  { id: 'sessions', label: 'Sessions' },
] as const
type TabId = (typeof TABS)[number]['id']

export default function AccountSettings() {
  const [tab, setTab] = useState<TabId>('profile')

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-lg font-semibold">Account</h1>

      <div className="flex gap-1 border-b border-border">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              'px-4 py-2 text-sm border-b-2 -mb-px transition-colors whitespace-nowrap',
              tab === t.id
                ? 'border-accent text-accent'
                : 'border-transparent text-muted hover:text-white',
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="space-y-8">
        {tab === 'profile' && <ProfileSection />}
        {tab === 'sessions' && <SessionsSection />}
      </div>
    </div>
  )
}
