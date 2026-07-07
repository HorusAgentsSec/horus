import { lazy, Suspense, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from './hooks/useAuth'
import { setSessionExpiredHandler, setBillingSuspendedHandler } from './lib/api'
import { Layout } from './components/layout/Layout'

// Each route is its own chunk: the initial download is just the shell + auth,
// and heavy pages (recharts, etc.) load on demand.
const Login = lazy(() => import('./pages/Login'))
const ChangePassword = lazy(() => import('./pages/ChangePassword'))
const Admin = lazy(() => import('./pages/Admin'))
const BillingInactive = lazy(() => import('./pages/BillingInactive'))
const StylePreview = lazy(() => import('./pages/StylePreview'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Assets = lazy(() => import('./pages/Assets'))
const Discovery = lazy(() => import('./pages/Discovery'))
const Watchtower = lazy(() => import('./pages/Watchtower'))
const Scans = lazy(() => import('./pages/Scans'))
const ScanDetail = lazy(() => import('./pages/ScanDetail'))
const Schedules = lazy(() => import('./pages/Schedules'))
const Jobs = lazy(() => import('./pages/Jobs'))
const Findings = lazy(() => import('./pages/Findings'))
const FindingDetail = lazy(() => import('./pages/FindingDetail'))
const Incidents = lazy(() => import('./pages/Incidents'))
const IncidentDetail = lazy(() => import('./pages/IncidentDetail'))
const Permissions = lazy(() => import('./pages/Permissions'))
const Team = lazy(() => import('./pages/Team'))
const Audit = lazy(() => import('./pages/Audit'))
const Integrations = lazy(() => import('./pages/Integrations'))
const Settings = lazy(() => import('./pages/Settings'))
const AccountSettings = lazy(() => import('./pages/AccountSettings'))
const Analytics = lazy(() => import('./pages/Analytics'))
const AssetDetail = lazy(() => import('./pages/AssetDetail'))
const Adversarial = lazy(() => import('./pages/Adversarial'))
const AdversarialDetail = lazy(() => import('./pages/AdversarialDetail'))
const AuthPhishing = lazy(() => import('./pages/AuthPhishing'))
const CredentialExposure = lazy(() => import('./pages/CredentialExposure'))
const Iris = lazy(() => import('./pages/Iris'))
const CloudSecurity = lazy(() => import('./pages/CloudSecurity'))
const NotFound = lazy(() => import('./pages/NotFound'))

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
    setBillingSuspendedHandler(() => {
      navigate('/billing-inactive', { replace: true })
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
      <Suspense fallback={<div className="min-h-screen bg-bg flex items-center justify-center text-muted text-sm">Loading…</div>}>
      <Routes>
        <Route path="/login" element={<Login />} />
        {/* Horus super-admin ops tool. Session-only (super-admins have no tenant profile);
            the backend enforces the SUPERADMIN_EMAILS allowlist. No nav link by design. */}
        <Route path="/admin" element={<RequireUser><Admin /></RequireUser>} />
        {/* Subscription lapsed past grace: the only reachable app screen (routes here on 402). */}
        <Route path="/billing-inactive" element={<RequireUser><BillingInactive /></RequireUser>} />
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
        {/* Public: the recovery email link lands here and opens its own session (detectSessionInUrl).
            No RequireUser guard — the guard would race the async token exchange. */}
        <Route path="/reset-password" element={<ChangePassword recovery />} />
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
          <Route path="incidents" element={<Incidents />} />
          <Route path="incidents/:id" element={<IncidentDetail />} />
          <Route path="permissions" element={<Permissions />} />
          <Route path="team" element={<Team />} />
          <Route path="audit" element={<Audit />} />
          <Route path="integrations" element={<Integrations />} />
          <Route path="settings" element={<Settings />} />
          <Route path="account" element={<AccountSettings />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="adversarial" element={<Adversarial />} />
          <Route path="adversarial/:id" element={<AdversarialDetail />} />
          <Route path="auth-phishing" element={<AuthPhishing />} />
          <Route path="credential-exposure" element={<CredentialExposure />} />
          <Route path="iris" element={<Iris />} />
          <Route path="cloud" element={<CloudSecurity />} />
          {/* Legacy paths (old bookmarks / muscle memory) — redirect, don't 404. */}
          <Route path="red-blue" element={<Navigate to="/adversarial" replace />} />
          <Route path="red-blue/:id" element={<Navigate to="/adversarial" replace />} />
          <Route path="audit-log" element={<Navigate to="/audit" replace />} />
          {/* Catch-all: friendly 404 inside the layout instead of a blank screen. */}
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
      </Suspense>
    </BrowserRouter>
  )
}
