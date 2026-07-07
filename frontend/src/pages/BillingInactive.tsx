import { useState } from 'react'
import { CreditCard, ShieldAlert } from 'lucide-react'
import { api, friendlyErrorMessage } from '../lib/api'
import { useUser } from '../contexts/UserContext'

// Shown when the org's subscription has lapsed past the grace period and the backend
// returns 402 on normal endpoints. The only action is to reach the Stripe portal and pay
// (that endpoint is exempt server-side). Non-admins are told to contact their admin.
export default function BillingInactive() {
  const { can, signOut } = useUser()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const isAdmin = can('admin')

  async function openPortal() {
    setLoading(true)
    setError(null)
    try {
      const { url } = await api.post<{ url: string }>('/billing/portal')
      window.location.href = url
    } catch (e) {
      setError(friendlyErrorMessage(e))
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-surface border border-border rounded-xl p-8 text-center">
        <ShieldAlert className="w-10 h-10 text-severity-high mx-auto mb-4" />
        <h1 className="text-lg font-semibold text-white mb-2">Subscription inactive</h1>
        <p className="text-sm text-muted leading-relaxed mb-6">
          Your Horus subscription has lapsed and access is paused. Reactivate it to restore
          your team's access. Your data is safe and waiting.
        </p>
        {error && <p className="text-xs text-severity-critical mb-4">{error}</p>}
        {isAdmin ? (
          <button
            onClick={openPortal}
            disabled={loading}
            className="inline-flex items-center gap-2 text-sm bg-accent text-bg px-5 py-2 rounded hover:bg-accent/90 transition-colors disabled:opacity-50"
          >
            <CreditCard className="w-4 h-4" />
            {loading ? 'Opening…' : 'Reactivate subscription'}
          </button>
        ) : (
          <p className="text-sm text-white">
            Please ask an administrator of your organization to update billing.
          </p>
        )}
        <div className="mt-6">
          <button onClick={signOut} className="text-xs text-muted hover:text-white transition-colors">
            Sign out
          </button>
        </div>
      </div>
    </div>
  )
}
