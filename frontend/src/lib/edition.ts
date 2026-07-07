// Open-core edition flag. "community" (default) is the AGPL open-source core and hides
// enterprise-only UI: the org switcher, non-email notification integrations, and Jira
// ticketing. The Horus-hosted SaaS builds with VITE_HORUS_EDITION=enterprise. The server
// is the real enforcement (402); this flag only keeps the UI honest.
export const EDITION = (import.meta.env.VITE_HORUS_EDITION ?? 'community').toLowerCase()
export const isEnterprise = EDITION === 'enterprise'
