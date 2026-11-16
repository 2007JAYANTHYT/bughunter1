import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useProgramStore } from '../stores/programStore'
import { Search, Filter, Download, Eye, Flag, Copy, Trash2, Globe } from 'lucide-react'
import { clsx } from 'clsx'

interface Finding {
  id: number
  program_id: number
  vuln_type: string
  severity: string
  title: string
  description: string
  status: string
  cvss_score: number | null
  cvss_vector: string
  tags: string[]
  created_at: string
  validated_at: string | null
  reported_at: string | null
  duplicate_of: number | null
}

interface FindingFilters {
  program_id?: number
  status?: string
  severity?: string
  vuln_type?: string
  is_reported?: boolean
  search?: string
  limit?: number
  offset?: number
}

export function Findings() {
  const { currentProgram } = useProgramStore()
  const queryClient = useQueryClient()

  const [filters, setFilters] = React.useState<FindingFilters>({
    program_id: currentProgram?.id,
    limit: 50,
    offset: 0,
  })

  const [search, setSearch] = React.useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['findings', filters],
    queryFn: async () => {
      const params = new URLSearchParams()
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') {
          params.append(key, String(value))
        }
      })
      const res = await fetch(`/api/findings?${params.toString()}`)
      if (!res.ok) throw new Error('Failed to fetch findings')
      return res.json() as Promise<Finding[]>
    },
  })

  const updateMutation = useMutation({
    mutationFn: async ({ id, updates }: { id: number; updates: Partial<Finding> }) => {
      const res = await fetch(`/api/findings/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      })
      if (!res.ok) throw new Error('Failed to update finding')
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
  })

  const handleStatusChange = (id: number, status: string) => {
    updateMutation.mutate({ id, updates: { status } })
  }

  const handleReport = (id: number) => {
    const url = prompt('Enter report URL:')
    if (url) {
      fetch(`/api/findings/${id}/report?report_url=${encodeURIComponent(url)}&platform=manual`, {
        method: 'POST',
      }).then(() => queryClient.invalidateQueries({ queryKey: ['findings'] }))
    }
  }

  const handleDuplicate = (id: number) => {
    const dupId = prompt('Enter duplicate finding ID:')
    if (dupId) {
      fetch(`/api/findings/${id}/duplicate?duplicate_of=${dupId}`, {
        method: 'POST',
      }).then(() => queryClient.invalidateQueries({ queryKey: ['findings'] }))
    }
  }

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setFilters(prev => ({ ...prev, search, offset: 0 }))
  }

  const severityOrder = { P1: 0, P2: 1, P3: 2, P4: 3 }
  const statusOrder = { new: 0, validated: 1, reported: 2, duplicate: 3, false_positive: 4, fixed: 5, paid: 6 }

  const sortedFindings = React.useMemo(() => {
    return [...(data || [])].sort((a, b) => {
      // Sort by severity first, then status, then date
      const sevDiff = (severityOrder[a.severity as keyof typeof severityOrder] ?? 99) -
                      (severityOrder[b.severity as keyof typeof severityOrder] ?? 99)
      if (sevDiff !== 0) return sevDiff

      const statusDiff = (statusOrder[a.status as keyof typeof statusOrder] ?? 99) -
                         (statusOrder[b.status as keyof typeof statusOrder] ?? 99)
      if (statusDiff !== 0) return statusDiff

      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    })
  }, [data])

  const stats = React.useMemo(() => {
    const counts = { total: 0, P1: 0, P2: 0, P3: 0, P4: 0, new: 0, validated: 0, reported: 0 }
    data?.forEach(f => {
      counts.total++
      counts[f.severity as keyof typeof counts]++
      counts[f.status as keyof typeof counts]++
    })
    return counts
  }, [data])

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Findings</h1>
          <p className="text-slate-500">Manage and track vulnerabilities</p>
        </div>
        <div className="flex items-center gap-2 text-sm text-slate-500">
          <span>Total: {stats.total}</span>
          <span className="badge badge-p1">P1: {stats.P1}</span>
          <span className="badge badge-p2">P2: {stats.P2}</span>
          <span className="badge badge-p3">P3: {stats.P3}</span>
          <span className="badge badge-p4">P4: {stats.P4}</span>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4">
        <form onSubmit={handleSearch} className="flex flex-wrap items-end gap-4">
          <div className="flex-1 min-w-[200px]">
            <label className="sr-only">Search</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search findings..."
                className="input pl-10"
              />
            </div>
          </div>

          <select
            value={filters.severity || ''}
            onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value || undefined, offset: 0 }))}
            className="select w-32"
          >
            <option value="">All Severities</option>
            <option value="P1">P1 - Critical</option>
            <option value="P2">P2 - High</option>
            <option value="P3">P3 - Medium</option>
            <option value="P4">P4 - Low</option>
          </select>

          <select
            value={filters.status || ''}
            onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value || undefined, offset: 0 }))}
            className="select w-36"
          >
            <option value="">All Statuses</option>
            <option value="new">New</option>
            <option value="validated">Validated</option>
            <option value="reported">Reported</option>
            <option value="duplicate">Duplicate</option>
            <option value="false_positive">False Positive</option>
            <option value="fixed">Fixed</option>
            <option value="paid">Paid</option>
          </select>

          <select
            value={filters.vuln_type || ''}
            onChange={(e) => setFilters(prev => ({ ...prev, vuln_type: e.target.value || undefined, offset: 0 }))}
            className="select w-40"
          >
            <option value="">All Types</option>
            <option value="xss">XSS</option>
            <option value="sqli">SQL Injection</option>
            <option value="ssrf">SSRF</option>
            <option value="rce">RCE</option>
            <option value="idor">IDOR</option>
            <option value="auth_bypass">Auth Bypass</option>
            <option value="logic">Business Logic</option>
            <option value="api">API</option>
            <option value="csrf">CSRF</option>
            <option value="xxe">XXE</option>
            <option value="ssti">SSTI</option>
          </select>

          <button type="submit" className="btn-primary">
            <Search className="w-4 h-4" />
            Filter
          </button>

          <button
            type="button"
            onClick={() => setFilters({ program_id: currentProgram?.id, limit: 50, offset: 0 })}
            className="btn-secondary"
          >
            <RotateCcw className="w-4 h-4" />
            Reset
          </button>
        </form>
      </div>

      {/* Findings Table */}
      <div className="card">
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th className="w-10">
                  <input
                    type="checkbox"
                    className="rounded border-slate-300"
                    onChange={(e) => {
                      document.querySelectorAll('input[name="finding-checkbox"]').forEach(cb => {
                        (cb as HTMLInputElement).checked = e.target.checked
                      })
                    }}
                  />
                </th>
                <th className="w-12">ID</th>
                <th>Title</th>
                <th className="w-28">Type</th>
                <th className="w-24">Severity</th>
                <th className="w-28">Status</th>
                <th className="w-20">CVSS</th>
                <th className="w-36">Created</th>
                <th className="w-48">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={9} className="text-center py-8">
                    <div className="flex items-center justify-center gap-2">
                      <svg className="animate-spin h-5 w-5 text-primary-600" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      Loading findings...
                    </div>
                  </td>
                </tr>
              ) : sortedFindings?.length === 0 ? (
                <tr>
                  <td colSpan={9} className="text-center py-12 text-slate-500">
                    No findings match the current filters
                  </td>
                </tr>
              ) : (
                sortedFindings?.map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <input
                        type="checkbox"
                        name="finding-checkbox"
                        value={finding.id}
                        className="rounded border-slate-300"
                      />
                    </td>
                    <td className="font-mono text-slate-500 text-sm">#{finding.id}</td>
                    <td className="font-medium text-slate-900 max-w-md truncate" title={finding.title}>
                      {finding.title}
                    </td>
                    <td className="text-slate-600 capitalize text-sm">
                      {finding.vuln_type.replace('_', ' ')}
                    </td>
                    <td>
                      <span className={clsx('badge', `badge-${finding.severity.toLowerCase()}`)}>
                        {finding.severity}
                      </span>
                    </td>
                    <td>
                      <span className={clsx('badge', `badge-${finding.status}`)}>
                        {finding.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="text-sm font-mono text-slate-600">
                      {finding.cvss_score?.toFixed(1) || '-'}
                    </td>
                    <td className="text-sm text-slate-500">
                      {new Date(finding.created_at).toLocaleDateString()}
                    </td>
                    <td>
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => window.open(`/api/evidence/${finding.id}`, '_blank')}
                          className="p-1.5 rounded hover:bg-slate-100 text-slate-500"
                          title="View Evidence"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleStatusChange(finding.id, 'validated')}
                          disabled={finding.status !== 'new' || updateMutation.isPending}
                          className="p-1.5 rounded hover:bg-slate-100 text-green-600"
                          title="Validate"
                        >
                          <Flag className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleReport(finding.id)}
                          disabled={finding.status === 'reported' || finding.status === 'false_positive'}
                          className="p-1.5 rounded hover:bg-slate-100 text-blue-600"
                          title="Mark Reported"
                        >
                          <Globe className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleDuplicate(finding.id)}
                          className="p-1.5 rounded hover:bg-slate-100 text-purple-600"
                          title="Mark Duplicate"
                        >
                          <Copy className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => handleStatusChange(finding.id, 'false_positive')}
                          disabled={finding.status === 'false_positive'}
                          className="p-1.5 rounded hover:bg-slate-100 text-red-600"
                          title="False Positive"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="p-4 border-t border-slate-200 flex items-center justify-between">
          <p className="text-sm text-slate-500">
            Showing {(filters.offset || 0) + 1} to {Math.min((filters.offset || 0) + (filters.limit || 50), data?.length || 0)} of {data?.length || 0} findings
          </p>
          <div className="flex gap-2">
            <button
              onClick={() => setFilters(prev => ({ ...prev, offset: Math.max(0, (prev.offset || 0) - (prev.limit || 50)) }))}
              disabled={(filters.offset || 0) === 0}
              className="btn-secondary"
            >
              Previous
            </button>
            <button
              onClick={() => setFilters(prev => ({ ...prev, offset: (prev.offset || 0) + (prev.limit || 50) }))}
              disabled={(data?.length || 0) <= (filters.offset || 0) + (filters.limit || 50)}
              className="btn-secondary"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

import React from 'react'