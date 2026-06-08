import { Component, type ReactNode } from 'react'
import { AlertTriangle } from 'lucide-react'

interface Props {
  children: ReactNode
}

interface State {
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: unknown) {
    console.error('Uncaught render error:', error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="min-h-screen bg-bg flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-surface border border-border rounded-xl p-6 text-center">
            <AlertTriangle className="w-8 h-8 text-severity-high mx-auto mb-4" />
            <h1 className="text-white font-semibold mb-2">Something went wrong</h1>
            <p className="text-sm text-muted mb-4">
              The app hit an unexpected error. Try reloading the page.
            </p>
            <pre className="text-xs text-severity-critical bg-bg border border-border rounded p-3 text-left overflow-x-auto mb-4">
              {this.state.error.message}
            </pre>
            <button
              onClick={() => window.location.reload()}
              className="text-sm bg-accent text-bg px-4 py-2 rounded hover:bg-accent/90 transition-colors"
            >
              Reload
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
