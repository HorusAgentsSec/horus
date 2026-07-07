import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Auth } from '@supabase/auth-ui-react'
import { ThemeSupa } from '@supabase/auth-ui-shared'
import { supabase } from '../lib/supabase'
import { Shield } from 'lucide-react'

// Cuenta demo read-only (role viewer). Credenciales públicas a propósito: la
// landing enlaza ?demo=1 y cualquiera puede entrar a mirar. El backend bloquea
// las escrituras de un viewer (require_role), así que no hay nada que proteger.
const DEMO_EMAIL = 'demo@horusagents.com'
const DEMO_PASSWORD = 'HorusDemo2026!'

export default function Login() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const sessionExpired = searchParams.get('expired') === '1'
  const isDemo = searchParams.get('demo') === '1'

  const [showForgot, setShowForgot] = useState(false)
  const [resetEmail, setResetEmail] = useState('')
  const [resetSent, setResetSent] = useState(false)
  const [resetErr, setResetErr] = useState<string | null>(null)
  const [resetting, setResetting] = useState(false)

  const sendReset = async () => {
    setResetErr(null)
    setResetting(true)
    try {
      // GoTrue returns success regardless of whether the email exists (no user enumeration),
      // and rate-limits this endpoint itself. Recovery rate limits live in the Supabase dashboard.
      const { error } = await supabase.auth.resetPasswordForEmail(resetEmail.trim(), {
        redirectTo: `${window.location.origin}/reset-password`,
      })
      if (error) throw new Error(error.message)
      setResetSent(true)
    } catch (e: unknown) {
      setResetErr(e instanceof Error ? e.message : 'Could not send reset email')
    } finally {
      setResetting(false)
    }
  }

  useEffect(() => {
    // Redirect if session already exists
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) {
        navigate('/dashboard', { replace: true })
      } else if (isDemo) {
        // Entra directo a la demo sin pedir nada. onAuthStateChange hace el navigate.
        void supabase.auth.signInWithPassword({ email: DEMO_EMAIL, password: DEMO_PASSWORD })
      }
    })

    // Redirigir tras login exitoso
    const { data: listener } = supabase.auth.onAuthStateChange((event) => {
      if (event === 'SIGNED_IN') navigate('/dashboard', { replace: true })
    })
    return () => listener.subscription.unsubscribe()
  }, [navigate, isDemo])

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2 justify-center mb-8">
          <Shield className="text-accent w-6 h-6" />
          <span className="text-xl font-semibold text-white">Horus</span>
        </div>
        {sessionExpired && (
          <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
            Your session expired. Please sign in again.
          </div>
        )}
        {isDemo ? (
          <div className="bg-surface border border-border rounded-xl p-6 text-center text-sm text-gray-400">
            Loading demo…
          </div>
        ) : (
        <div className="bg-surface border border-border rounded-xl p-6">
          <Auth
            supabaseClient={supabase}
            view="sign_in"
            showLinks={false}
            appearance={{
              theme: ThemeSupa,
              variables: {
                default: {
                  colors: {
                    brand: '#58a6ff',
                    brandAccent: '#79b8ff',
                    inputBackground: '#0f1117',
                    inputBorder: '#30363d',
                    inputText: '#ffffff',
                    inputPlaceholder: '#8b949e',
                  },
                },
              },
            }}
            providers={[]}
          />

          <div className="mt-4 border-t border-border pt-4">
            {!showForgot ? (
              <button
                onClick={() => setShowForgot(true)}
                className="text-xs text-muted hover:text-white transition-colors"
              >
                Forgot your password?
              </button>
            ) : resetSent ? (
              <p className="text-xs text-muted">
                If an account exists for that address, a reset link is on its way. Check your inbox.
              </p>
            ) : (
              <div className="space-y-2">
                <label className="text-xs text-muted block">
                  Enter your email and we'll send a reset link.
                </label>
                <input
                  type="email"
                  value={resetEmail}
                  onChange={(e) => setResetEmail(e.target.value)}
                  placeholder="you@company.com"
                  autoComplete="email"
                  className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-accent"
                />
                {resetErr && <p className="text-xs text-severity-critical">{resetErr}</p>}
                <div className="flex items-center gap-2">
                  <button
                    onClick={sendReset}
                    disabled={!resetEmail.trim() || resetting}
                    className="bg-accent text-bg text-sm font-medium px-4 py-2 rounded hover:bg-accent/90 transition-colors disabled:opacity-50"
                  >
                    {resetting ? 'Sending…' : 'Send reset link'}
                  </button>
                  <button
                    onClick={() => setShowForgot(false)}
                    className="text-xs text-muted hover:text-white transition-colors"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
        )}
      </div>
    </div>
  )
}
