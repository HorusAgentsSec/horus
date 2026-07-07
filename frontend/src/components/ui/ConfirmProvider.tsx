import { createContext, useCallback, useContext, useRef, useState } from 'react'
import { Modal } from '../Modal'
import { cn } from '../../lib/utils'

/**
 * App-styled replacements for the browser's blocking window.confirm / window.alert.
 * Both return a promise, so callsites stay one-liners:
 *
 *   const confirm = useConfirm()
 *   if (!(await confirm('Delete this asset?'))) return
 *
 *   const alert = useAlert()
 *   await alert('Failed to revoke key')
 */

interface DialogOptions {
  title?: string
  message: React.ReactNode
  confirmLabel?: string
  cancelLabel?: string
  /** Style the confirm button as destructive. */
  danger?: boolean
}

type ConfirmInput = string | DialogOptions
type AlertInput = string | Omit<DialogOptions, 'cancelLabel' | 'danger'>

interface ConfirmContextValue {
  confirm: (input: ConfirmInput) => Promise<boolean>
  alert: (input: AlertInput) => Promise<void>
}

const ConfirmContext = createContext<ConfirmContextValue | null>(null)

interface DialogState extends DialogOptions {
  mode: 'confirm' | 'alert'
}

const normalize = (input: ConfirmInput | AlertInput): DialogOptions =>
  typeof input === 'string' ? { message: input } : input

export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<DialogState | null>(null)
  const resolver = useRef<((value: boolean) => void) | null>(null)

  const close = useCallback((result: boolean) => {
    resolver.current?.(result)
    resolver.current = null
    setState(null)
  }, [])

  const confirm = useCallback((input: ConfirmInput) => {
    setState({ ...normalize(input), mode: 'confirm' })
    return new Promise<boolean>((resolve) => { resolver.current = resolve })
  }, [])

  const alert = useCallback((input: AlertInput) => {
    setState({ ...normalize(input), mode: 'alert' })
    return new Promise<boolean>((resolve) => { resolver.current = resolve }).then(() => {})
  }, [])

  return (
    <ConfirmContext.Provider value={{ confirm, alert }}>
      {children}
      <Modal
        open={state !== null}
        onClose={() => close(false)}
        title={state?.title ?? (state?.mode === 'confirm' ? 'Confirm' : 'Notice')}
      >
        <div className="space-y-5">
          <p className="text-sm text-white/80 whitespace-pre-line">{state?.message}</p>
          <div className="flex justify-end gap-3">
            {state?.mode === 'confirm' && (
              <button
                onClick={() => close(false)}
                className="text-sm text-muted hover:text-white transition-colors px-2"
              >
                {state?.cancelLabel ?? 'Cancel'}
              </button>
            )}
            <button
              onClick={() => close(true)}
              autoFocus
              className={cn(
                'text-sm px-4 py-1.5 rounded transition-colors',
                state?.danger
                  ? 'bg-severity-critical text-white hover:bg-severity-critical/90'
                  : 'bg-accent text-bg hover:bg-accent/90',
              )}
            >
              {state?.confirmLabel ?? (state?.mode === 'confirm' ? 'Confirm' : 'OK')}
            </button>
          </div>
        </div>
      </Modal>
    </ConfirmContext.Provider>
  )
}

export function useConfirm() {
  const ctx = useContext(ConfirmContext)
  if (!ctx) throw new Error('useConfirm must be used within ConfirmProvider')
  return ctx.confirm
}

export function useAlert() {
  const ctx = useContext(ConfirmContext)
  if (!ctx) throw new Error('useAlert must be used within ConfirmProvider')
  return ctx.alert
}
