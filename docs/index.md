# Horus Documentation

Horus is a security automation platform for small IT teams. It discovers your attack surface, scans for vulnerabilities, correlates findings against live threat intelligence, and surfaces only what needs your attention.

## Sections

| Document | Description |
|---|---|
| [Overview](overview.md) | What Horus is, architecture diagram, tech stack, and deployment targets |
| [API Reference](api-reference.md) | All REST endpoints grouped by resource, with request/response shapes |
| [Agents](agents.md) | The multi-agent AI pipeline: stages, each agent's role, token budget management |
| [Scanners](scanners.md) | Nmap, Nuclei, ZAP scanners; CVE/EPSS/HIBP/IntelX threat intel; SSVC prioritization |
| [Data Models](data-models.md) | Database schema, RLS policies, soft deletes, Mermaid ERD |
| [Iris](iris.md) | The Rust monitoring daemon: monitors, configuration, event schema, installation |
| [Security](security.md) | Auth (Supabase JWT), roles, API keys, RLS, rate limiting, security headers |
| [Frontend](frontend.md) | React app: routes, pages, layout, state management, auth flow |
| [Deployment](deployment.md) | Local Docker Compose, environment variables, Fly.io, Cloudflare Pages |

## Quick links

- Local setup: [Deployment > Local development](deployment.md#local-development)
- All API endpoints: [API Reference](api-reference.md)
- How the AI pipeline works: [Agents](agents.md)
- Database tables: [Data Models](data-models.md)
- Iris installation: [Iris > Installation](iris.md#installation)
- Role definitions: [Security > Authorization](security.md#authorization)
