import { Eye, ShieldCheck, AlertTriangle, ArrowRight, Activity } from 'lucide-react'
import { GlassCard } from '../components/GlassCard'

/**
 * Isolated showcase for the "Horus + liquid glass" visual direction.
 * Reachable at /preview. Does not touch any real screen — it only exercises the
 * new tokens (horus.*) and glass utilities so the look can be validated.
 */

const SWATCHES: { name: string; cls: string; hex: string }[] = [
  { name: 'Night', cls: 'bg-horus-night border border-white/10', hex: '#0A0E1A' },
  { name: 'Lapis', cls: 'bg-horus-lapis', hex: '#2C6BED' },
  { name: 'Gold', cls: 'bg-horus-gold', hex: '#E8B94A' },
  { name: 'Turquoise', cls: 'bg-horus-turquoise', hex: '#27C2B6' },
  { name: 'Carnelian', cls: 'bg-horus-carnelian', hex: '#D6453B' },
  { name: 'Ivory', cls: 'bg-horus-ivory', hex: '#F4EFE6' },
]

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span
      className="text-[11px] font-medium px-2 py-0.5 rounded-full border"
      style={{ color, borderColor: `${color}55`, background: `${color}1a` }}
    >
      {label}
    </span>
  )
}

export default function StylePreview() {
  return (
    <div className="horus-bg min-h-screen text-horus-ivory p-8">
      <div className="max-w-5xl mx-auto space-y-8">
        {/* Brand */}
        <header className="flex items-center gap-3">
          <div className="glass specular rounded-xl w-11 h-11 flex items-center justify-center">
            <Eye className="w-6 h-6 text-horus-gold" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Horus</h1>
            <p className="text-sm text-white/50">Liquid-glass visual direction · lapis-dominant</p>
          </div>
        </header>

        {/* Palette */}
        <GlassCard className="p-6">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-white/60 mb-4">Palette</h2>
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-4">
            {SWATCHES.map((s) => (
              <div key={s.name} className="space-y-2">
                <div className={`${s.cls} h-14 rounded-xl shadow-inner`} />
                <div className="text-xs">
                  <div className="text-white/80">{s.name}</div>
                  <div className="text-white/40 font-mono">{s.hex}</div>
                </div>
              </div>
            ))}
          </div>
        </GlassCard>

        {/* Stat + finding cards */}
        <div className="grid md:grid-cols-3 gap-6">
          <GlassCard interactive className="p-6">
            <div className="flex items-center gap-2 text-white/60 text-sm mb-3">
              <Activity className="w-4 h-4 text-horus-lapis" /> Risk score
            </div>
            <div className="text-4xl font-semibold">43</div>
            <div className="mt-2 text-sm text-horus-turquoise">▼ 12 over 90 days · lower is better</div>
          </GlassCard>

          <GlassCard interactive className="p-6 md:col-span-2">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-horus-gold" />
                <span className="font-medium">nginx 1.18.0 — 6 CVEs</span>
              </div>
              <Badge label="Act · SSVC" color="#D6453B" />
            </div>
            <div className="flex flex-wrap gap-2 mb-4">
              <Badge label="critical" color="#D6453B" />
              <Badge label="high" color="#E8B94A" />
              <Badge label="actively exploited" color="#2C6BED" />
              <Badge label="KEV" color="#27C2B6" />
            </div>
            <p className="text-sm text-white/60">
              Detected on bw.bse.eu. Correlated against CISA KEV + EPSS. Two CVEs are actively exploited.
            </p>
          </GlassCard>
        </div>

        {/* Buttons / controls */}
        <GlassCard className="p-6">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-white/60 mb-4">Actions</h2>
          <div className="flex flex-wrap items-center gap-3">
            <button className="inline-flex items-center gap-2 bg-horus-lapis hover:brightness-110 text-white text-sm font-medium px-4 py-2 rounded-lg transition">
              <ShieldCheck className="w-4 h-4" /> Run scan
            </button>
            <button className="inline-flex items-center gap-2 glass glass-hover text-horus-gold text-sm font-medium px-4 py-2 rounded-lg">
              View report <ArrowRight className="w-4 h-4" />
            </button>
            <button className="text-sm text-white/60 hover:text-white px-4 py-2 rounded-lg transition">
              Dismiss
            </button>
            <input
              className="glass rounded-lg px-3 py-2 text-sm text-white placeholder:text-white/40 focus:outline-none focus:border-horus-lapis ml-auto w-56"
              placeholder="Search assets, findings…"
            />
          </div>
        </GlassCard>

        <p className="text-center text-xs text-white/30">
          Preview only · /preview · tokens <span className="font-mono">horus.*</span> + <span className="font-mono">.glass</span> utilities
        </p>
      </div>
    </div>
  )
}
