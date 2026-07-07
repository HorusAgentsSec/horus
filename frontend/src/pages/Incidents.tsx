import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertCircle, Plus, Clock } from 'lucide-react'
import {
  incidentsApi,
  friendlyErrorMessage,
  type IncidentSummary,
  type IncidentSeverity,
} from '../lib/api'
import { SeverityBadge } from '../components/findings/SeverityBadge'
import { StatusBadge, SlaCountdown } from '../components/incidents/IncidentBadges'
import { Select } from '../components/ui/Select'
import { Modal } from '../components/Modal'

const STATUS_FILTERS = ['', 'open', 'in_progress', 'resolved', 'closed']
const SEVERITY_FILTERS = ['', 'critical', 'high', 'medium', 'low']

function isOverdue(deadline: string | null, status: string): boolean {
  if (!deadline) return false
  if (status === 'resolved' || status === 'closed') return false
  return new Date(deadline).getTime() < Date.now()
}

export default function Incidents() {
  const navigate = useNavigate()
  const [incidents, setIncidents] = useState<IncidentSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const [showCreate, setShowCreate] = useState(false)

  const load = () => {
    setLoading(true)
    incidentsApi
      .list({ status: status || undefined, severity: severity || undefined })
      .then((data) => setIncidents(data.items))
      .finally(() => setLoading(false))
  }

  useEffect(load, [status, severity])

  const stats = useMemo(() => {
    const open = incidents.filter((i) => i.status === 'open' || i.status === 'in_progress').length
    const critical = incidents.filter((i) => i.severity === 'critical' && i.status !== 'closed').length
    const overdue = incidents.filter((i) => isOverdue(i.sla_deadline, i.status)).length
    return { open, critical, overdue }
  }, [incidents])

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-horus-ivory flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-horus-gold" /> Incidents
          </h1>
          <p className="text-sm text-muted mt-1">
            Group related findings, assign an owner, and track SLAs.
          </p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 text-sm bg-horus-lapis text-white px-3 py-2 rounded-md hover:opacity-90 transition-opacity"
        >
          <Plus className="w-4 h-4" /> New Incident
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Open" value={stats.open} />
        <StatCard label="Critical" value={stats.critical} accent="text-severity-critical" />
        <StatCard label="Overdue SLA" value={stats.overdue} accent="text-severity-high" />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Select
          value={status}
          onValueChange={(v) => setStatus(v)}
          options={STATUS_FILTERS.map((s) => ({ value: s, label: s ? s.replace('_', ' ') : 'All statuses' }))}
        />
        <Select
          value={severity}
          onValueChange={(v) => setSeverity(v)}
          options={SEVERITY_FILTERS.map((s) => ({ value: s, label: s || 'All severities' }))}
        />
      </div>

      {/* List */}
      {loading ? (
        <p className="text-muted text-sm">Loading…</p>
      ) : incidents.length === 0 ? (
        <div className="glass rounded-lg p-8 text-center">
          <AlertCircle className="w-8 h-8 text-muted mx-auto mb-2" />
          <p className="text-muted text-sm">No incidents yet. Create one to start tracking.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {incidents.map((inc) => (
            <button
              key={inc.id}
              onClick={() => navigate(`/incidents/${inc.id}`)}
              className="glass glass-hover rounded-lg p-4 w-full text-left flex items-center gap-4 transition-colors"
            >
              <SeverityBadge severity={inc.severity} />
              <div className="min-w-0 flex-1">
                <p className="text-horus-ivory font-medium truncate">{inc.title}</p>
                <p className="text-xs text-muted mt-0.5">
                  {inc.finding_count} finding{inc.finding_count === 1 ? '' : 's'}
                  {inc.assignee?.name || inc.assignee?.email ? (
                    <> · {inc.assignee.name || inc.assignee.email}</>
                  ) : (
                    <> · Unassigned</>
                  )}
                </p>
              </div>
              <SlaCountdown deadline={inc.sla_deadline} status={inc.status} />
              <StatusBadge status={inc.status} />
            </button>
          ))}
        </div>
      )}

      {showCreate && (
        <CreateIncidentModal
          onClose={() => setShowCreate(false)}
          onCreated={(id) => {
            setShowCreate(false)
            navigate(`/incidents/${id}`)
          }}
        />
      )}
    </div>
  )
}

function StatCard({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="glass rounded-lg p-4">
      <p className="text-xs text-muted uppercase tracking-wide">{label}</p>
      <p className={`text-2xl font-semibold mt-1 ${accent ?? 'text-horus-ivory'}`}>{value}</p>
    </div>
  )
}

function CreateIncidentModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (id: string) => void
}) {
  const [title, setTitle] = useState('')
  const [severity, setSeverity] = useState<IncidentSeverity>('medium')
  const [slaDeadline, setSlaDeadline] = useState('')
  const [assignee, setAssignee] = useState('')
  const [description, setDescription] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const submit = async () => {
    if (!title.trim() || saving) return
    setSaving(true)
    setError('')
    try {
      const created = await incidentsApi.create({
        title: title.trim(),
        severity,
        description: description.trim() || undefined,
        // assignee is free text for now (no user picker yet); only send if it looks like a UUID.
        assignee_id: /^[0-9a-f-]{36}$/i.test(assignee.trim()) ? assignee.trim() : undefined,
        sla_deadline: slaDeadline ? new Date(slaDeadline).toISOString() : undefined,
      })
      onCreated(created.id)
    } catch (e) {
      setError(friendlyErrorMessage(e, 'Could not create the incident'))
      setSaving(false)
    }
  }

  return (
    <Modal open onClose={onClose} title="New Incident" className="max-w-lg">
      <div className="space-y-4">
        <Field label="Title">
          <input
            autoFocus
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="e.g. Exposed admin panel on prod"
            className="w-full glass rounded-md px-3 py-2 text-sm text-horus-ivory bg-transparent border border-white/10"
          />
        </Field>

        <div className="grid grid-cols-2 gap-4">
          <Field label="Severity">
            <Select
              className="w-full"
              value={severity}
              onValueChange={(v) => setSeverity(v as IncidentSeverity)}
              options={(['critical', 'high', 'medium', 'low'] as IncidentSeverity[]).map((s) => ({ value: s, label: s }))}
            />
          </Field>
          <Field label="SLA deadline">
            <input
              type="date"
              value={slaDeadline}
              onChange={(e) => setSlaDeadline(e.target.value)}
              className="w-full glass rounded-md px-3 py-2 text-sm text-horus-ivory bg-transparent border border-white/10"
            />
          </Field>
        </div>

        <Field label="Assignee (user ID, optional)">
          <input
            value={assignee}
            onChange={(e) => setAssignee(e.target.value)}
            placeholder="UUID of a team member"
            className="w-full glass rounded-md px-3 py-2 text-sm text-horus-ivory bg-transparent border border-white/10"
          />
        </Field>

        <Field label="Description (optional)">
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
            className="w-full glass rounded-md px-3 py-2 text-sm text-horus-ivory bg-transparent border border-white/10 resize-none"
          />
        </Field>

        {error && <p className="text-xs text-severity-high">{error}</p>}

        <div className="flex justify-end gap-2 pt-2">
          <button
            onClick={onClose}
            className="text-sm text-muted hover:text-white px-3 py-2"
          >
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={!title.trim() || saving}
            className="flex items-center gap-2 text-sm bg-horus-lapis text-white px-4 py-2 rounded-md hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Clock className="w-4 h-4" /> {saving ? 'Creating…' : 'Create'}
          </button>
        </div>
      </div>
    </Modal>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-muted uppercase tracking-wide">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  )
}
