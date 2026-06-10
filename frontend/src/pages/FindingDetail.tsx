import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, ExternalLink, Ticket } from 'lucide-react'
import { api, jiraApi, friendlyErrorMessage, type JiraStatus, type JiraTicket } from '../lib/api'
import { FindingDetailView } from '../components/findings/FindingDetail'

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [finding, setFinding] = useState<unknown>(null)
  const [suggestions, setSuggestions] = useState<unknown[]>([])
  const [loading, setLoading] = useState(true)
  const [jiraStatus, setJiraStatus] = useState<JiraStatus | null>(null)
  const [ticket, setTicket] = useState<JiraTicket | null>(null)
  const [creatingTicket, setCreatingTicket] = useState(false)
  const [ticketError, setTicketError] = useState('')

  const load = async () => {
    if (!id) return
    const [f, s] = await Promise.all([
      api.get(`/findings/${id}`),
      api.get(`/findings/${id}/suggestions`),
    ])
    setFinding(f)
    setSuggestions(s as unknown[])
    setLoading(false)
    // Jira is optional context — never block the finding render on it.
    jiraApi.status().then(setJiraStatus).catch(() => setJiraStatus(null))
    jiraApi.getTickets(id).then((t) => setTicket(t[0] ?? null)).catch(() => {})
  }

  const createTicket = async () => {
    if (!id || creatingTicket) return
    setTicketError('')
    setCreatingTicket(true)
    try {
      const t = await jiraApi.createTicket(id)
      setTicket(t)
    } catch (e) {
      setTicketError(friendlyErrorMessage(e, 'Could not create the Jira ticket'))
    } finally {
      setCreatingTicket(false)
    }
  }

  useEffect(() => { load() }, [id])

  const handleApprove = async (suggestionId: string) => {
    await api.post(`/suggestions/${suggestionId}/approve`)
    load()
  }

  const handleReject = async (suggestionId: string) => {
    await api.post(`/suggestions/${suggestionId}/reject`)
    load()
  }

  const handleStatusChange = async (newStatus: string) => {
    if (!id) return
    await api.patch(`/findings/${id}`, { status: newStatus })
    load()
  }

  const backButton = (
    <button
      onClick={() => navigate('/findings')}
      className="flex items-center gap-2 text-sm text-muted hover:text-white transition-colors mb-4"
    >
      <ArrowLeft className="w-4 h-4" /> Back to Findings
    </button>
  )

  if (loading) return <div>{backButton}<p className="text-muted text-sm">Loading…</p></div>
  if (!finding) return <div>{backButton}<p className="text-muted text-sm">Finding not found.</p></div>

  const jiraReady = !!jiraStatus?.configured && !!jiraStatus?.enabled
  const jiraControl = ticket ? (
    <a
      href={ticket.ticket_url}
      target="_blank"
      rel="noreferrer"
      className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-1.5 rounded-md hover:bg-accent/20 transition-colors"
      title="Open the linked Jira issue"
    >
      <Ticket className="w-4 h-4" /> {ticket.ticket_key}
      <ExternalLink className="w-3.5 h-3.5" />
    </a>
  ) : (
    <button
      onClick={createTicket}
      disabled={!jiraReady || creatingTicket}
      title={
        !jiraStatus?.configured
          ? 'Jira is not configured — an admin can add it under Integrations'
          : !jiraStatus?.enabled
          ? 'The Jira integration is disabled — enable it under Integrations'
          : 'Create a Jira issue from this finding'
      }
      className="flex items-center gap-1.5 text-sm bg-accent/10 text-accent px-3 py-1.5 rounded-md hover:bg-accent/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
    >
      <Ticket className="w-4 h-4" /> {creatingTicket ? 'Creating…' : 'Create Jira ticket'}
    </button>
  )

  return (
    <div>
      <div className="flex items-start justify-between gap-4">
        {backButton}
        <div className="flex flex-col items-end gap-1">
          {jiraControl}
          {ticketError && <p className="text-xs text-severity-high max-w-xs text-right">{ticketError}</p>}
        </div>
      </div>
      <FindingDetailView
        finding={finding as Parameters<typeof FindingDetailView>[0]['finding']}
        suggestions={suggestions as Parameters<typeof FindingDetailView>[0]['suggestions']}
        onApprove={handleApprove}
        onReject={handleReject}
        onStatusChange={handleStatusChange}
      />
    </div>
  )
}
