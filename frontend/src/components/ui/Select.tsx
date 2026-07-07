import * as RSelect from '@radix-ui/react-select'
import { Check, ChevronDown } from 'lucide-react'
import { cn } from '../../lib/utils'

export interface SelectOption {
  value: string
  label: React.ReactNode
  disabled?: boolean
}

// Radix Select forbids an empty-string value (it's reserved for clearing/placeholder).
// Filters across the app use value="" to mean "All", so we transparently swap it for a
// sentinel internally and swap back on change. Callsites keep using "" as before.
const EMPTY = '__empty__'
const enc = (v: string) => (v === '' ? EMPTY : v)
const dec = (v: string) => (v === EMPTY ? '' : v)

interface SelectProps {
  value: string
  onValueChange: (value: string) => void
  /** Convenience: render a flat list of options. For custom items, pass children instead. */
  options?: SelectOption[]
  children?: React.ReactNode
  placeholder?: string
  disabled?: boolean
  /** Extra classes for the trigger (e.g. "w-full"). */
  className?: string
  'aria-label'?: string
}

/**
 * App-styled dropdown built on Radix Select: glass popover, keyboard nav,
 * typeahead and ARIA for free. Drop-in replacement for a native <select> —
 * pass `options`, or compose <SelectItem> children for custom rows.
 */
export function Select({
  value, onValueChange, options, children, placeholder, disabled, className, ...rest
}: SelectProps) {
  return (
    <RSelect.Root value={enc(value)} onValueChange={(v) => onValueChange(dec(v))} disabled={disabled}>
      <RSelect.Trigger
        aria-label={rest['aria-label']}
        className={cn(
          'flex items-center justify-between gap-2 rounded-md border border-white/10 bg-bg/60',
          'px-3 py-2 text-sm text-horus-ivory transition-colors',
          'hover:border-white/20 focus:outline-none focus:border-accent',
          'data-[placeholder]:text-muted disabled:opacity-50 disabled:cursor-not-allowed',
          className,
        )}
      >
        <RSelect.Value placeholder={placeholder} />
        <RSelect.Icon className="text-muted">
          <ChevronDown className="w-4 h-4" />
        </RSelect.Icon>
      </RSelect.Trigger>
      <RSelect.Portal>
        <RSelect.Content
          position="popper"
          sideOffset={4}
          className={cn(
            'z-[60] min-w-[var(--radix-select-trigger-width)] overflow-hidden',
            // Opacity-only fade: a transform-based animation would fight the inline
            // transform Radix's popper uses to position the content, causing a flash.
            'glass border border-white/10 rounded-lg shadow-2xl animate-fade-in',
          )}
        >
          <RSelect.Viewport className="p-1 max-h-[min(20rem,var(--radix-select-content-available-height))]">
            {options
              ? options.map((o) => (
                  <SelectItem key={o.value} value={o.value} disabled={o.disabled}>
                    {o.label}
                  </SelectItem>
                ))
              : children}
          </RSelect.Viewport>
        </RSelect.Content>
      </RSelect.Portal>
    </RSelect.Root>
  )
}

export function SelectItem({
  value, children, disabled,
}: { value: string; children: React.ReactNode; disabled?: boolean }) {
  return (
    <RSelect.Item
      value={enc(value)}
      disabled={disabled}
      className={cn(
        'relative flex items-center gap-2 rounded px-3 py-1.5 pr-8 text-sm text-horus-ivory',
        'cursor-pointer select-none outline-none',
        'data-[highlighted]:bg-white/10 data-[state=checked]:text-accent',
        'data-[disabled]:opacity-40 data-[disabled]:cursor-not-allowed',
      )}
    >
      <RSelect.ItemText>{children}</RSelect.ItemText>
      <RSelect.ItemIndicator className="absolute right-2.5 inline-flex">
        <Check className="w-3.5 h-3.5" />
      </RSelect.ItemIndicator>
    </RSelect.Item>
  )
}
