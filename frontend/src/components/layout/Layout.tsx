import { Suspense, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { CommandPalette } from '../CommandPalette'

export function Layout() {
  const [navOpen, setNavOpen] = useState(false)
  const location = useLocation()

  return (
    <div className="flex h-screen horus-bg text-horus-ivory overflow-hidden">
      <Sidebar open={navOpen} onClose={() => setNavOpen(false)} />
      <div className="flex-1 flex flex-col min-w-0 z-0">
        <Header onMenuClick={() => setNavOpen(true)} />
        <main className="flex-1 overflow-y-auto p-4 sm:p-6">
          {/* Keyed by route so the entrance animation replays on navigation. */}
          <div key={location.pathname} className="animate-page-enter">
            <Suspense
              fallback={
                <div className="flex items-center justify-center py-24 text-white/40">
                  <Loader2 className="w-5 h-5 animate-spin" />
                </div>
              }
            >
              <Outlet />
            </Suspense>
          </div>
        </main>
      </div>
      <CommandPalette />
    </div>
  )
}
