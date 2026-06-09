import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from './hooks/useAuth'
import { setSessionExpiredHandler } from './lib/api'
import { Layout } from './components/layout/Layout'
import Login from './pages/Login'
import ChangePassword from './pages/ChangePassword'
import StylePreview from './pages/StylePreview'
import Dashboard from './pages/Dashboard'
import Assets from './pages/Assets'
import Discovery from './pages/Discovery'
import Watchtower from './pages/Watchtower'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import Schedules from './pages/Schedules'
import Jobs from './pages/Jobs'
import Findings from './pages/Findings'
import FindingDetail from './pages/FindingDetail'
import Permissions from './pages/Permissions'
import Team from './pages/Team'
import Audit from './pages/Audit'
import Integrations from './pages/Integrations'
import Settings from './pages/Settings'
import Analytics from './pages/Analytics'
import AssetDetail from './pages/AssetDetail'
import Adversarial from './pages/Adversarial'
import AdversarialDetail from './pages/AdversarialDetail'
import AuthPhishing from './pages/AuthPhishing'
import CredentialExposure from './pages/CredentialExposure'

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { user, loading, mustChangePassword } = useAuth()
  if (loading) return <div className="min-h-screen bg-bg flex items-center justify-center text-muted text-sm">Loading…</div>
  if (!user) return <Navigate to="/login" replace />
  if (mustChangePassword) return <Navigate to="/change-password" replace />
  return <>{children}</>
}

// Requires a session but does NOT enforce the password-change gate, so the
// change-password screen itself stays reachable.
function RequireUser({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="min-h-screen bg-bg flex items-center justify-center text-muted text-sm">Loading…</div>
  if (!user) return <Navigate to="/login" replace />
  return <>{children}</>
}

// Routes the user to a clean re-login when the API reports an unrecoverable
// auth failure, instead of letting a raw 401/500 surface in the UI.
function SessionWatcher() {
  const navigate = useNavigate()
  const { signOut } = useAuth()
  useEffect(() => {
    setSessionExpiredHandler(() => {
      signOut()
      navigate('/login?expired=1', { replace: true })
    })
  }, [navigate, signOut])
  return null
}

import { ShortcutsOverlay } from './components/ShortcutsOverlay'

export default function App() {
  return (
    <BrowserRouter>
      <ShortcutsOverlay />
      <SessionWatcher />
      <Routes>
        <Route path="/login" element={<Login />} />
        {/* Isolated showcase for the Horus + liquid-glass visual direction. */}
        <Route path="/preview" element={<StylePreview />} />
        <Route
          path="/change-password"
          element={
            <RequireUser>
              <ChangePassword />
            </RequireUser>
          }
        />
        <Route
          path="/"
          element={
            <PrivateRoute>
              <Layout />
            </PrivateRoute>
          }
        >
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="assets" element={<Assets />} />
          <Route path="assets/:id" element={<AssetDetail />} />
          <Route path="discovery" element={<Discovery />} />
          <Route path="watchtower" element={<Watchtower />} />
          <Route path="scans" element={<Scans />} />
          <Route path="scans/:id" element={<ScanDetail />} />
          <Route path="schedules" element={<Schedules />} />
          <Route path="jobs" element={<Jobs />} />
          <Route path="findings" element={<Findings />} />
          <Route path="findings/:id" element={<FindingDetail />} />
          <Route path="permissions" element={<Permissions />} />
          <Route path="team" element={<Team />} />
          <Route path="audit" element={<Audit />} />
          <Route path="integrations" element={<Integrations />} />
          <Route path="settings" element={<Settings />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="adversarial" element={<Adversarial />} />
          <Route path="adversarial/:id" element={<AdversarialDetail />} />
          <Route path="auth-phishing" element={<AuthPhishing />} />
          <Route path="credential-exposure" element={<CredentialExposure />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
