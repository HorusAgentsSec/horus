import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'
import { UserProvider } from './contexts/UserContext'
import { ErrorBoundary } from './components/ErrorBoundary'
import { ConfirmProvider } from './components/ui/ConfirmProvider'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <UserProvider>
        <ConfirmProvider>
          <App />
        </ConfirmProvider>
      </UserProvider>
    </ErrorBoundary>
  </StrictMode>,
)
