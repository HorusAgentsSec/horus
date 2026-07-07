import { Link, useLocation } from 'react-router-dom'
import { Compass, ArrowLeft } from 'lucide-react'

// Friendly catch-all for unknown URLs (mistyped deep-links, stale bookmarks) so the
// app never renders a blank screen. Known legacy paths are redirected in App.tsx.
export default function NotFound() {
  const { pathname } = useLocation()
  return (
    <div className="flex flex-col items-center justify-center text-center py-24 gap-3">
      <div className="glass specular rounded-lg w-12 h-12 flex items-center justify-center">
        <Compass className="w-6 h-6 text-horus-gold" />
      </div>
      <h1 className="text-lg font-semibold text-white mt-2">Page not found</h1>
      <p className="text-sm text-muted max-w-sm">
        <code className="text-white/70">{pathname}</code> doesn&apos;t exist or may have moved.
      </p>
      <Link
        to="/dashboard"
        className="mt-2 flex items-center gap-2 px-3 py-1.5 rounded-md border border-white/10 text-sm text-white/70 hover:text-white hover:border-white/30 transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        Back to dashboard
      </Link>
    </div>
  )
}
