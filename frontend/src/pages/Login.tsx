import { useEffect } from 'react'
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
