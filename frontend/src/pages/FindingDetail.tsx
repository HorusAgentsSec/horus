import { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import { api } from '../lib/api'
import { FindingDetailView } from '../components/findings/FindingDetail'

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [finding, setFinding] = useState<unknown>(null)
  const [suggestions, setSuggestions] = useState<unknown[]>([])
  const [loading, setLoading] = useState(true)

  const load = async () => {
    if (!id) return
    const [f, s] = await Promise.all([
      api.get(`/findings/${id}`),
      api.get(`/findings/${id}/suggestions`),
    ])
    setFinding(f)
    setSuggestions(s as unknown[])
    setLoading(false)
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

  if (loading) return <p className="text-muted text-sm">Loading…</p>
  if (!finding) return <p className="text-muted text-sm">Finding not found.</p>

  return (
    <FindingDetailView
      finding={finding as Parameters<typeof FindingDetailView>[0]['finding']}
      suggestions={suggestions as Parameters<typeof FindingDetailView>[0]['suggestions']}
      onApprove={handleApprove}
      onReject={handleReject}
      onStatusChange={handleStatusChange}
    />
  )
}
