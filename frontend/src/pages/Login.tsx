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

async function enterDemo() {
  await supabase.auth.signInWithPassword({ email: DEMO_EMAIL, password: DEMO_PASSWORD })
}

export default function Login() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const sessionExpired = searchParams.get('expired') === '1'
  const isDemo = searchParams.get('demo') === '1'

  const [email, setEmail] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) navigate('/dashboard', { replace: true })
    })

    const { data: listener } = supabase.auth.onAuthStateChange((event) => {
      if (event === 'SIGNED_IN') navigate('/dashboard', { replace: true })
    })
    return () => listener.subscription.unsubscribe()
  }, [navigate])

  async function handleDemoSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setError('')

    // ponytail: no bloquear la demo si falla el envío, solo logueamos
    await fetch('/api/demo-lead', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email.trim() }),
    }).catch(err => console.error('demo-lead:', err))

    await enterDemo()
    // navigate se dispara via onAuthStateChange
  }

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
          <div className="bg-surface border border-border rounded-xl p-6">
            <p className="text-white font-medium mb-1">Acceder a la demo</p>
            <p className="text-gray-400 text-sm mb-5">Introduce tu email para continuar.</p>
            <form onSubmit={handleDemoSubmit} className="space-y-3">
              <input
                type="email"
                placeholder="Email de trabajo"
                required
                value={email}
                onChange={e => setEmail(e.target.value)}
                className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-accent"
              />
              {error && <p className="text-red-400 text-xs">{error}</p>}
              <button
                type="submit"
                disabled={submitting}
                className="w-full bg-accent hover:bg-accent/90 disabled:opacity-50 text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors"
              >
                {submitting ? 'Entrando…' : 'Ver la demo'}
              </button>
            </form>
          </div>
        ) : (
          <div className="bg-surface border border-border rounded-xl p-6">
            <Auth
              supabaseClient={supabase}
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
          </div>
        )}
      </div>
    </div>
  )
}
