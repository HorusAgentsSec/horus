import { useEffect, useState } from 'react'
import { api, friendlyErrorMessage } from '../lib/api'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  BarChart,
  Bar,
  Cell,
  PieChart,
  Pie,
} from 'recharts'
import { Brain, Cpu, Coins, AlertCircle } from 'lucide-react'

interface MetricsData {
  total_tokens: number
  by_agent: Record<string, number>
  by_model: Record<string, number>
  daily_usage: { date: string; tokens: number }[]
}

const COLORS = ['#58a6ff', '#3fb950', '#ff8c00', '#ffd700', '#ff4444', '#8b949e', '#ab7df6']

export default function Analytics() {
  const [data, setData] = useState<MetricsData | null>(null)
  const [days, setDays] = useState<number>(30)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState<boolean>(true)

  useEffect(() => {
    setLoading(true)
    setError(null)
    api.get<MetricsData>(`/metrics/tokens?days=${days}`)
      .then((res) => {
        setData(res)
      })
      .catch((err) => {
        setError(friendlyErrorMessage(err, 'Failed to load token usage statistics.'))
      })
      .finally(() => {
        setLoading(false)
      })
  }, [days])

  if (loading && !data) {
    return <div className="text-muted text-sm p-6">Loading analytics data…</div>
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="bg-severity-critical/10 border border-severity-critical text-severity-critical rounded-lg p-4 flex items-center gap-2">
          <AlertCircle className="w-5 h-5 shrink-0" />
          <span>{error}</span>
        </div>
      </div>
    )
  }

  const agentData = data
    ? Object.entries(data.by_agent).map(([name, value]) => ({ name, value }))
    : []
  const modelData = data
    ? Object.entries(data.by_model).map(([name, value]) => ({ name, value }))
    : []

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-lg font-semibold">Analytics Dashboard</h1>
          <p className="text-xs text-muted">Monitor agent token consumption and LLM costs</p>
        </div>
        <select
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="bg-surface border border-border rounded px-3 py-1 text-sm text-white focus:outline-none focus:ring-1 focus:ring-accent"
        >
          <option value={7}>Last 7 Days</option>
          <option value={30}>Last 30 Days</option>
          <option value={90}>Last 90 Days</option>
        </select>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-surface border border-border rounded-lg p-4">
          <div className="flex items-center gap-2 text-muted mb-2">
            <Coins className="w-4 h-4 text-accent" />
            <span className="text-xs uppercase">Total Tokens Used</span>
          </div>
          <p className="text-2xl font-semibold text-white">
            {data?.total_tokens.toLocaleString() ?? 0}
          </p>
        </div>
        <div className="bg-surface border border-border rounded-lg p-4">
          <div className="flex items-center gap-2 text-muted mb-2">
            <Brain className="w-4 h-4 text-mode-auto" />
            <span className="text-xs uppercase">Unique Models</span>
          </div>
          <p className="text-2xl font-semibold text-white">
            {Object.keys(data?.by_model ?? {}).length}
          </p>
        </div>
        <div className="bg-surface border border-border rounded-lg p-4">
          <div className="flex items-center gap-2 text-muted mb-2">
            <Cpu className="w-4 h-4 text-severity-high" />
            <span className="text-xs uppercase">Active Agents</span>
          </div>
          <p className="text-2xl font-semibold text-white">
            {Object.keys(data?.by_agent ?? {}).length}
          </p>
        </div>
      </div>

      {/* Daily Usage Line/Area Chart */}
      <div className="bg-surface border border-border rounded-lg p-6">
        <h2 className="text-sm font-medium text-white mb-4 uppercase tracking-wider">Token Consumption Over Time</h2>
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data?.daily_usage ?? []}>
              <defs>
                <linearGradient id="colorTokens" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#58a6ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#58a6ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#30363d" strokeDasharray="3 3" />
              <XAxis dataKey="date" stroke="#8b949e" fontSize={12} tickLine={false} />
              <YAxis stroke="#8b949e" fontSize={12} tickLine={false} tickFormatter={(v) => v >= 1000 ? `${(v/1000).toFixed(0)}k` : v} />
              <Tooltip
                contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d', color: 'white' }}
                labelClassName="text-white text-xs font-semibold"
                itemStyle={{ color: '#58a6ff', fontSize: '12px' }}
              />
              <Area type="monotone" dataKey="tokens" stroke="#58a6ff" fillOpacity={1} fill="url(#colorTokens)" strokeWidth={2} name="Tokens" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Breakdown grids */}
      <div className="grid grid-cols-2 gap-6">
        {/* Token Usage by Agent */}
        <div className="bg-surface border border-border rounded-lg p-6">
          <h2 className="text-sm font-medium text-white mb-4 uppercase tracking-wider">Usage by Agent Type</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={agentData}>
                <CartesianGrid stroke="#30363d" strokeDasharray="3 3" />
                <XAxis dataKey="name" stroke="#8b949e" fontSize={12} tickLine={false} />
                <YAxis stroke="#8b949e" fontSize={12} tickLine={false} tickFormatter={(v) => v >= 1000 ? `${(v/1000).toFixed(0)}k` : v} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d' }}
                  itemStyle={{ color: 'white', fontSize: '12px' }}
                />
                <Bar dataKey="value" fill="#58a6ff" radius={[4, 4, 0, 0]} name="Tokens">
                  {agentData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Token Usage by Model */}
        <div className="bg-surface border border-border rounded-lg p-6">
          <h2 className="text-sm font-medium text-white mb-4 uppercase tracking-wider">Usage by Model</h2>
          <div className="h-64 flex items-center justify-center">
            {modelData.length > 0 ? (
              <div className="flex w-full items-center justify-around h-full">
                <div className="w-1/2 h-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={modelData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        paddingAngle={5}
                        dataKey="value"
                      >
                        {modelData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ backgroundColor: '#161b22', borderColor: '#30363d' }}
                        itemStyle={{ color: 'white', fontSize: '12px' }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="w-1/2 space-y-2">
                  {modelData.map((m, idx) => (
                    <div key={m.name} className="flex items-center gap-2 text-xs">
                      <span className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: COLORS[idx % COLORS.length] }} />
                      <span className="text-muted truncate max-w-[150px]">{m.name}</span>
                      <span className="text-white font-medium ml-auto">
                        {((m.value / (data?.total_tokens || 1)) * 100).toFixed(1)}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-sm text-muted">No model usage data available</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
