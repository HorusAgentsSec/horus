import { type ReactNode } from 'react'
import { cn } from '../lib/utils'

interface GlassCardProps {
  children: ReactNode
  className?: string
  /** Adds a subtle interactive lift + glow on hover. */
  interactive?: boolean
}

/**
 * Liquid-glass surface primitive for the Horus visual direction: frosted
 * translucency, a luminous hairline border and a specular top highlight.
 * Sits on top of a `.horus-bg` background.
 */
export function GlassCard({ children, className, interactive }: GlassCardProps) {
  return (
    <div className={cn('glass specular rounded-2xl', interactive && 'glass-hover', className)}>
      {children}
    </div>
  )
}
