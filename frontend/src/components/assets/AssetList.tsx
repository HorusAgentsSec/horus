import { Play, Trash2, ArrowUp, ArrowDown } from 'lucide-react'
import { useState, useMemo } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { api, friendlyErrorMessage } from '../../lib/api'
import { cn } from '../../lib/utils'
import { useConfirm } from '../ui/ConfirmProvider'
import type { Asset } from '../../hooks/useAssets'

interface Props {
  assets: Asset[]
  onRefresh: () => void
}

type SortCol = 'name' | 'host' | 'type' | 'is_internal'

export function AssetList({ assets, onRefresh }: Props) {
  const [actionError, setActionError] = useState<string | null>(null)
  const [scanningAssetId, setScanningAssetId] = useState<string | null>(null)
  const [sortCol, setSortCol] = useState<SortCol>('name')
  const [sortDesc, setSortDesc] = useState(false)
  const navigate = useNavigate()
  const confirm = useConfirm()

  const sortedAssets = useMemo(() => {
    return [...assets].sort((a, b) => {
      const va = a[sortCol]
      const vb = b[sortCol]
      if (va < vb) return sortDesc ? 1 : -1
      if (va > vb) return sortDesc ? -1 : 1
      return 0
    })
  }, [assets, sortCol, sortDesc])

  const triggerScan = async (assetId: string) => {
    setActionError(null)
    setScanningAssetId(assetId)
    try {
      const scan = await api.post<{ scan_id: string; status: string }>(
        '/scans',
        { asset_id: assetId, tools: ['nuclei', 'nmap'] },
      )
      navigate(`/scans/${scan.scan_id}`)
    } catch (e: unknown) {
      setActionError(friendlyErrorMessage(e, 'Failed to start scan'))
    } finally {
      setScanningAssetId(null)
    }
  }

  const deleteAsset = async (assetId: string) => {
    if (!(await confirm({ message: 'Delete this asset?', danger: true, confirmLabel: 'Delete' }))) return
    setActionError(null)
    try {
      await api.delete(`/assets/${assetId}`)
      onRefresh()
    } catch (e: unknown) {
      setActionError(friendlyErrorMessage(e, 'Failed to delete asset'))
    }
  }

  const Th = ({ col, label }: { col: SortCol, label: string }) => (
    <th 
      className="text-left py-3 px-4 font-medium cursor-pointer hover:bg-white/5 select-none" 
      onClick={() => {
        if (sortCol === col) setSortDesc(!sortDesc)
        else { setSortCol(col); setSortDesc(false) }
      }}
    >
      <div className="flex items-center gap-1">
        {label}
        {sortCol === col && (sortDesc ? <ArrowDown className="w-3 h-3" /> : <ArrowUp className="w-3 h-3" />)}
      </div>
    </th>
  )

  return (
    <div className="space-y-3">
      {actionError && (
        <div className="border border-severity-critical/40 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical">
          {actionError}
        </div>
      )}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-xs text-muted">
              <Th col="name" label="Name" />
              <Th col="host" label="Host" />
              <Th col="type" label="Type" />
              <Th col="is_internal" label="Scope" />
              <th className="text-left py-3 px-4 font-medium">Tags</th>
              <th className="py-3 px-4" />
            </tr>
          </thead>
          <tbody>
            {sortedAssets.map((asset) => (
              <tr key={asset.id} className="border-b border-border hover:bg-white/[0.02] transition-colors">
                <td className="py-3 px-4 font-medium text-white">
                  <Link to={`/assets/${asset.id}`} className="hover:underline">{asset.name}</Link>
                </td>
                <td className="py-3 px-4 text-muted font-mono text-xs">
                  {asset.host}{asset.port ? `:${asset.port}` : ''}
                </td>
                <td className="py-3 px-4">
                  <span className="text-xs text-muted uppercase">{asset.type}</span>
                </td>
                <td className="py-3 px-4">
                  <span className={cn('text-xs', asset.is_internal ? 'text-mode-auto' : 'text-severity-medium')}>
                    {asset.is_internal ? 'Internal' : 'External'}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <div className="flex flex-wrap gap-1">
                    {asset.tags.map((t) => (
                      <span key={t} className="text-xs bg-accent/10 text-accent px-1.5 py-0.5 rounded">{t}</span>
                    ))}
                  </div>
                </td>
                <td className="py-3 px-4">
                  <div className="flex items-center gap-2 justify-end">
                    <button
                      onClick={() => triggerScan(asset.id)}
                      disabled={scanningAssetId !== null}
                      className="text-muted hover:text-mode-auto transition-colors disabled:cursor-wait disabled:opacity-50"
                      title={scanningAssetId === asset.id ? 'Starting scan' : 'Scan now'}
                    >
                      <Play className="w-3.5 h-3.5" />
                    </button>
                    <button onClick={() => deleteAsset(asset.id)} className="text-muted hover:text-severity-critical transition-colors" title="Delete">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
