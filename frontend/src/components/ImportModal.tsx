import { useState, useRef } from 'react'
import { Upload, X } from 'lucide-react'
import { api } from '../lib/api'

interface ImportResult {
  imported: number
  skipped: number
  total: number
}

interface ImportModalProps {
  open: boolean
  onClose: () => void
  onSuccess: () => void
}

export function ImportModal({ open, onClose, onSuccess }: ImportModalProps) {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [source, setSource] = useState<'nuclei' | 'generic'>('nuclei')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ImportResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  if (!open) return null

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) {
      setFile(f)
      setError(null)
    }
  }

  const handleImport = async () => {
    if (!file) {
      setError('Please select a file')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const formData = new FormData()
      formData.append('file', file)
      formData.append('source', source)

      const response = await fetch('/api/findings/import', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${(await (window as any).supabase?.auth?.getSession?.())?.data?.session?.access_token || ''}`,
        },
        body: formData,
      })

      if (!response.ok) {
        const body = await response.json()
        throw new Error(body.detail || `Import failed (${response.status})`)
      }

      const data = (await response.json()) as ImportResult
      setResult(data)
      onSuccess()

      setTimeout(() => {
        onClose()
        setFile(null)
        setResult(null)
      }, 2000)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Import failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-surface border border-border rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Import findings</h2>
          <button
            onClick={onClose}
            className="p-1 hover:bg-border rounded transition text-muted hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {result ? (
          <div className="space-y-2 text-sm">
            <p className="text-success">Import completed</p>
            <p className="text-muted">
              Imported: <span className="text-white">{result.imported}</span>
            </p>
            <p className="text-muted">
              Skipped: <span className="text-white">{result.skipped}</span>
            </p>
          </div>
        ) : (
          <>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-muted uppercase tracking-wide block mb-1.5">
                  Source format
                </label>
                <select
                  value={source}
                  onChange={(e) => setSource(e.target.value as 'nuclei' | 'generic')}
                  disabled={loading}
                  className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-accent transition"
                >
                  <option value="nuclei">Nuclei (JSONL)</option>
                  <option value="generic">Generic JSON array</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-muted uppercase tracking-wide block mb-1.5">
                  File
                </label>
                <button
                  onClick={() => fileInputRef.current?.click()}
                  disabled={loading}
                  className="w-full border-2 border-dashed border-border rounded-lg p-4 hover:border-accent transition flex flex-col items-center gap-2 text-muted hover:text-white disabled:opacity-50"
                >
                  <Upload className="w-5 h-5" />
                  <span className="text-xs">
                    {file ? file.name : 'Choose file or drag & drop'}
                  </span>
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  hidden
                  onChange={handleFileChange}
                  accept=".json,.jsonl,.txt,.csv"
                  disabled={loading}
                />
              </div>
            </div>

            {error && <p className="text-xs text-severity-critical">{error}</p>}

            <div className="flex gap-2 pt-2">
              <button
                onClick={handleImport}
                disabled={!file || loading}
                className="flex-1 bg-accent text-bg px-4 py-2 rounded text-sm font-medium hover:bg-accent/90 disabled:opacity-50 transition"
              >
                {loading ? 'Importing...' : 'Import'}
              </button>
              <button
                onClick={onClose}
                disabled={loading}
                className="flex-1 bg-border text-muted hover:bg-border/80 px-4 py-2 rounded text-sm transition disabled:opacity-50"
              >
                Cancel
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
