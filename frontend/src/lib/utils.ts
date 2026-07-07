import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
export type Severity = typeof SEVERITY_ORDER[number]

export function severityColor(severity: Severity | string): string {
  const map: Record<string, string> = {
    critical: 'text-severity-critical',
    high: 'text-severity-high',
    medium: 'text-severity-medium',
    low: 'text-severity-low',
    info: 'text-severity-info',
  }
  return map[severity] ?? 'text-muted'
}

export function severityBg(severity: Severity | string): string {
  const map: Record<string, string> = {
    critical: 'bg-severity-critical/10 border-severity-critical/30',
    high: 'bg-severity-high/10 border-severity-high/30',
    medium: 'bg-severity-medium/10 border-severity-medium/30',
    low: 'bg-severity-low/10 border-severity-low/30',
    info: 'bg-severity-info/10 border-severity-info/30',
  }
  return map[severity] ?? 'bg-surface border-border'
}

export function modeBadgeColor(mode: string): string {
  const map: Record<string, string> = {
    auto: 'bg-mode-auto/10 text-mode-auto border-mode-auto/30',
    approval_required: 'bg-mode-approval/10 text-mode-approval border-mode-approval/30',
    suggest_only: 'bg-surface text-muted border-border',
  }
  return map[mode] ?? 'bg-surface text-muted border-border'
}
