import { Outlet } from 'react-router-dom'
import { Sidebar } from './Sidebar'
import { Header } from './Header'
import { CommandPalette } from '../CommandPalette'

export function Layout() {
  return (
    <div className="flex h-screen horus-bg text-horus-ivory overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0 z-0">
        <Header />
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
      <CommandPalette />
    </div>
  )
}
