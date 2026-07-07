import * as Dialog from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import { cn } from '../lib/utils'

interface ModalProps {
  open: boolean
  onClose: () => void
  /** Visible heading. Always rendered (visually hidden if omitted) for a11y. */
  title?: React.ReactNode
  children: React.ReactNode
  /** Override the panel width / classes (e.g. "max-w-2xl"). */
  className?: string
}

/**
 * Accessible modal built on Radix Dialog: focus trap, scroll lock, Escape and
 * backdrop-click to close, and a portaled overlay that escapes any clipping
 * stacking context. Controlled via `open` / `onClose`.
 */
export function Modal({ open, onClose, title, children, className }: ModalProps) {
  return (
    <Dialog.Root open={open} onOpenChange={(o) => { if (!o) onClose() }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm animate-fade-in" />
        <Dialog.Content
          className={cn(
            'fixed left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2',
            'w-[calc(100%-2rem)] max-w-sm glass border border-white/10 rounded-xl p-6 shadow-2xl',
            'focus:outline-none animate-modal-in',
            className,
          )}
        >
          {title ? (
            <div className="flex items-center justify-between mb-4">
              <Dialog.Title className="text-lg font-semibold text-horus-ivory">{title}</Dialog.Title>
              <Dialog.Close
                aria-label="Close"
                className="p-1 -mr-1 rounded text-white/50 hover:text-white hover:bg-white/10 transition-colors"
              >
                <X className="w-4 h-4" />
              </Dialog.Close>
            </div>
          ) : (
            <Dialog.Title className="sr-only">Dialog</Dialog.Title>
          )}
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
