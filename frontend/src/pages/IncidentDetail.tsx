import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Check, Pencil, Plus, Send, Trash2 } from 'lucide-react'
import {
  incidentsApi,
  friendlyErrorMessage,
  type IncidentDetail,
  type IncidentSeverity,
  type IncidentStatus,
} from '../lib/api'
import { SeverityBadge } from '../components/findings/SeverityBadge'
import { StatusBadge, SlaCountdown } from '../components/incidents/IncidentBadges'
import { Select } from '../components/ui/Select'

const STATUSES: IncidentStatus[] = ['open', 'in_progress', 'resolved', 'closed']
const SEVERITIES: IncidentSeverity[] = ['critical', 'high', 'medium', 'low']

function initials(person: { name: string | null; email: string | null } | null): string {
  const source = person?.name || person?.email || '?'
  const parts = source.trim().split(/\s+/)
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase()
  return source.slice(0, 2).toUpperCase()
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export default function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [incident, setIncident] = useState<IncidentDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)

  const load = () => {
    if (!id) return
    incidentsApi
      .get(id)
      .then(setIncident)
      .catch(() => setNotFound(true))
      .finally(() => setLoading(false))
  }

  useEffect(load, [id])

  const patch = async (body: Parameters<typeof incidentsApi.update>[1]) => {
    if (!id) return
    await incidentsApi.update(id, body)
    load()
  }

  const back = (
    <button
      onClick={() => navigate('/incidents')}
      className="flex items-center gap-2 text-sm text-muted hover:text-white transition-colors mb-4"
    >
      <ArrowLeft className="w-4 h-4" /> Back to Incidents
    </button>
  )

  if (loading) return <div>{back}<p className="text-muted text-sm">Loading…</p></div>
  if (notFound || !incident) return <div>{back}<p className="text-muted text-sm">Incident not found.</p></div>

  return (
    <div className="max-w-4xl">
      {back}

      <Header incident={incident} onPatch={patch} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
        <FindingsSection incident={incident} onChange={load} />
        <ActivitySection incident={incident} onChange={load} />
      </div>
    </div>
  )
}

function Header({
  incident,
  onPatch,
}: {
  incident: IncidentDetail
  onPatch: (body: Parameters<typeof incidentsApi.update>[1]) => Promise<void>
}) {
  const [editingTitle, setEditingTitle] = useState(false)
  const [title, setTitle] = useState(incident.title)

  const saveTitle = async () => {
    setEditingTitle(false)
    if (title.trim() && title.trim() !== incident.title) {
      await onPatch({ title: title.trim() })
    } else {
      setTitle(incident.title)
    }
  }

  return (
    <div className="glass rounded-lg p-5 space-y-4">
      <div className="flex items-start gap-3">
        {editingTitle ? (
          <input
            autoFocus
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            onBlur={saveTitle}
            onKeyDown={(e) => {
              if (e.key === 'Enter') saveTitle()
              if (e.key === 'Escape') {
                setTitle(incident.title)
                setEditingTitle(false)
              }
            }}
            className="flex-1 text-xl font-semibold text-horus-ivory bg-transparent border-b border-white/20 focus:outline-none focus:border-horus-gold"
          />
        ) : (
          <button
            onClick={() => setEditingTitle(true)}
            className="flex-1 text-left group flex items-center gap-2"
          >
            <span className="text-xl font-semibold text-horus-ivory">{incident.title}</span>
            <Pencil className="w-4 h-4 text-muted opacity-0 group-hover:opacity-100 transition-opacity" />
          </button>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-4">
        <div>
          <p className="text-xs text-muted uppercase tracking-wide mb-1">Severity</p>
          <Select
            value={incident.severity}
            onValueChange={(v) => onPatch({ severity: v as IncidentSeverity })}
            options={SEVERITIES.map((s) => ({ value: s, label: s }))}
          />
        </div>

        <div>
          <p className="text-xs text-muted uppercase tracking-wide mb-1">Status</p>
          <Select
            value={incident.status}
            onValueChange={(v) => onPatch({ status: v as IncidentStatus })}
            options={STATUSES.map((s) => ({ value: s, label: s.replace('_', ' ') }))}
          />
        </div>

        <div>
          <p className="text-xs text-muted uppercase tracking-wide mb-1">Assignee</p>
          <p className="text-sm text-horus-ivory">
            {incident.assignee?.name || incident.assignee?.email || 'Unassigned'}
          </p>
        </div>

        <div>
          <p className="text-xs text-muted uppercase tracking-wide mb-1">SLA</p>
          <SlaCountdown deadline={incident.sla_deadline} status={incident.status} />
        </div>
      </div>

      {incident.description && (
        <p className="text-sm text-white/80 whitespace-pre-wrap border-t border-white/10 pt-3">
          {incident.description}
        </p>
      )}
    </div>
  )
}

function FindingsSection({
  incident,
  onChange,
}: {
  incident: IncidentDetail
  onChange: () => void
}) {
  const [adding, setAdding] = useState(false)
  const [findingId, setFindingId] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const addFinding = async () => {
    const value = findingId.trim()
    if (!value || busy) return
    setBusy(true)
    setError('')
    try {
      const res = await incidentsApi.addFindings(incident.id, [value])
      if (res.linked === 0) {
        setError('No matching finding in this org for that ID.')
      } else {
        setFindingId('')
        setAdding(false)
        onChange()
      }
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Could not link the finding'))
    } finally {
      setBusy(false)
    }
  }

  const unlink = async (fid: string) => {
    await incidentsApi.removeFinding(incident.id, fid)
    onChange()
  }

  return (
    <section className="glass rounded-lg p-5">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-horus-ivory uppercase tracking-wide">
          Findings ({incident.findings.length})
        </h2>
        <button
          onClick={() => setAdding((v) => !v)}
          className="flex items-center gap-1 text-xs text-horus-gold hover:opacity-80"
        >
          <Plus className="w-3.5 h-3.5" /> Link
        </button>
      </div>

      {adding && (
        <div className="mb-3 space-y-1">
          <div className="flex gap-2">
            <input
              autoFocus
              value={findingId}
              onChange={(e) => setFindingId(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addFinding()}
              placeholder="Finding ID"
              className="flex-1 glass rounded-md px-3 py-1.5 text-sm text-horus-ivory bg-transparent border border-white/10"
            />
            <button
              onClick={addFinding}
              disabled={busy}
              className="text-sm bg-horus-lapis text-white px-3 rounded-md hover:opacity-90 disabled:opacity-40"
            >
              <Check className="w-4 h-4" />
            </button>
          </div>
          {error && <p className="text-xs text-severity-high">{error}</p>}
        </div>
      )}

      {incident.findings.length === 0 ? (
        <p className="text-sm text-muted">No findings linked yet.</p>
      ) : (
        <ul className="space-y-2">
          {incident.findings.map((f) => (
            <li key={f.id} className="flex items-center gap-3 glass-hover rounded-md px-3 py-2">
              {f.severity && <SeverityBadge severity={f.severity} />}
              <a
                href={`/findings/${f.id}`}
                className="flex-1 min-w-0 text-sm text-horus-ivory truncate hover:text-horus-gold"
              >
                {f.title || f.id}
              </a>
              <button
                onClick={() => unlink(f.id)}
                title="Unlink finding"
                className="text-muted hover:text-severity-high"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function ActivitySection({
  incident,
  onChange,
}: {
  incident: IncidentDetail
  onChange: () => void
}) {
  const [body, setBody] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    const value = body.trim()
    if (!value || busy) return
    setBusy(true)
    try {
      await incidentsApi.addNote(incident.id, value)
      setBody('')
      onChange()
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="glass rounded-lg p-5 flex flex-col">
      <h2 className="text-sm font-semibold text-horus-ivory uppercase tracking-wide mb-3">
        Activity
      </h2>

      <div className="flex-1 space-y-4 mb-4">
        {incident.notes.length === 0 ? (
          <p className="text-sm text-muted">No activity yet.</p>
        ) : (
          incident.notes.map((note) => (
            <div key={note.id} className="flex gap-3">
              <div className="w-8 h-8 shrink-0 rounded-full glass flex items-center justify-center text-xs font-medium text-horus-gold">
                {initials(note.author)}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline gap-2">
                  <span className="text-sm font-medium text-horus-ivory">
                    {note.author?.name || note.author?.email || 'Unknown'}
                  </span>
                  <span className="text-xs text-muted">{formatTime(note.created_at)}</span>
                </div>
                <p className="text-sm text-white/80 whitespace-pre-wrap mt-0.5">{note.body}</p>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="flex gap-2 border-t border-white/10 pt-3">
        <input
          value={body}
          onChange={(e) => setBody(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && submit()}
          placeholder="Add a note…"
          className="flex-1 glass rounded-md px-3 py-2 text-sm text-horus-ivory bg-transparent border border-white/10"
        />
        <button
          onClick={submit}
          disabled={!body.trim() || busy}
          className="text-sm bg-horus-lapis text-white px-3 rounded-md hover:opacity-90 disabled:opacity-40"
        >
          <Send className="w-4 h-4" />
        </button>
      </div>
    </section>
  )
}
