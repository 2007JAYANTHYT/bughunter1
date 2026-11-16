import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Copy, Download, Flag, Globe, Trash2, Edit2, AlertTriangle, Shield, FileCode, Image, Video, Terminal, Database, Zap } from 'lucide-react'
import { clsx } from 'clsx'

interface Finding {
  id: number
  program_id: number
  target_id: number
  endpoint_id: number
  vuln_type: string
  severity: string
  title: string
  description: string
  evidence: Record<string, any>
  poc: string
  status: string
  cvss_score: number | null
  cvss_vector: string
  impact: string
  remediation: string
  tags: string[]
  created_at: string
  validated_at: string | null
  reported_at: string | null
  duplicate_of: number | null
  evidence_items: EvidenceItem[]
}

interface EvidenceItem {
  id: number
  type: string
  path: string
  description: string
  metadata: Record<string, any>
  created_at: string
}

export function FindingDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const { data: finding, isLoading } = useQuery({
    queryKey: ['finding', id],
    queryFn: async () => {
      const res = await fetch(`/api/findings/${id}`)
      if (!res.ok) throw new Error('Failed to fetch finding')
      return res.json() as Promise<Finding>
    },
  })

  const updateMutation = useMutation({
    mutationFn: async (updates: Partial<Finding>) => {
      const res = await fetch(`/api/findings/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      })
      if (!res.ok) throw new Error('Failed to update finding')
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', id] })
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
  })

  const handleStatusChange = (status: string) => {
    updateMutation.mutate({ status })
  }

  const handleReport = () => {
    const url = prompt('Enter report URL:')
    if (url) {
      fetch(`/api/findings/${id}/report?report_url=${encodeURIComponent(url)}&platform=manual`, {
        method: 'POST',
      }).then(() => queryClient.invalidateQueries({ queryKey: ['finding', id] }))
    }
  }

  const handleDuplicate = () => {
    const dupId = prompt('Enter duplicate finding ID:')
    if (dupId) {
      fetch(`/api/findings/${id}/duplicate?duplicate_of=${dupId}`, {
        method: 'POST',
      }).then(() => queryClient.invalidateQueries({ queryKey: ['finding', id] }))
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <svg className="animate-spin h-8 w-8 text-primary-600" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
      </div>
    )
  }

  if (!finding) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-slate-300 mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-slate-900">Finding not found</h2>
        <button onClick={() => navigate('/findings')} className="btn-primary mt-4">
          Back to Findings
        </button>
      </div>
    )
  }

  const severityColors = {
    P1: 'badge-p1 bg-red-100 text-red-800 border-red-200',
    P2: 'badge-p2 bg-orange-100 text-orange-800 border-orange-200',
    P3: 'badge-p3 bg-yellow-100 text-yellow-800 border-yellow-200',
    P4: 'badge-p4 bg-green-100 text-green-800 border-green-200',
  }

  const statusColors = {
    new: 'badge-new bg-blue-100 text-blue-800 border-blue-200',
    validated: 'badge-validated bg-green-100 text-green-800 border-green-200',
    reported: 'badge-reported bg-amber-100 text-amber-800 border-amber-200',
    duplicate: 'badge-duplicate bg-purple-100 text-purple-800 border-purple-200',
    false_positive: 'badge-false_positive bg-red-100 text-red-800 border-red-200',
    fixed: 'badge-fixed bg-emerald-100 text-emerald-800 border-emerald-200',
    paid: 'badge-paid bg-yellow-100 text-yellow-800 border-yellow-200',
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <button onClick={() => navigate(-1)} className="p-2 rounded-lg hover:bg-slate-100 text-slate-500">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-slate-900">{finding.title}</h1>
              <span className={clsx('badge', severityColors[finding.severity as keyof typeof severityColors])}>
                {finding.severity}
              </span>
              <span className={clsx('badge', statusColors[finding.status as keyof typeof statusColors])}>
                {finding.status.replace('_', ' ')}
              </span>
              {finding.cvss_score && (
                <span className="badge bg-slate-100 text-slate-800 border-slate-200">
                  CVSS: {finding.cvss_score.toFixed(1)}
                </span>
              )}
            </div>
            <p className="text-sm text-slate-500 mt-1">
              ID: #{finding.id} • {finding.vuln_type.replace('_', ' ')} • {new Date(finding.created_at).toLocaleDateString()}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleReport}
            disabled={finding.status === 'reported' || finding.status === 'false_positive'}
            className="btn-primary"
          >
            <Globe className="w-4 h-4" />
            Mark Reported
          </button>
          <button
            onClick={handleDuplicate}
            className="btn-secondary"
          >
            <Copy className="w-4 h-4" />
            Mark Duplicate
          </button>
          <button
            onClick={() => handleStatusChange('false_positive')}
            disabled={finding.status === 'false_positive'}
            className="btn-danger"
          >
            <Trash2 className="w-4 h-4" />
            False Positive
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Description */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <FileCode className="w-5 h-5 text-slate-500" />
              Description
            </h3>
            <div className="prose prose-slate max-w-none">
              <p className="whitespace-pre-wrap text-slate-700">{finding.description || 'No description provided.'}</p>
            </div>
          </div>

          {/* Impact */}
          {finding.impact && (
            <div className="card p-6 border-l-4 border-red-500">
              <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-600" />
                Impact
              </h3>
              <div className="prose prose-slate max-w-none">
                <p className="whitespace-pre-wrap text-slate-700">{finding.impact}</p>
              </div>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div className="card p-6 border-l-4 border-green-500">
              <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
                <Shield className="w-5 h-5 text-green-600" />
                Remediation
              </h3>
              <div className="prose prose-slate max-w-none">
                <p className="whitespace-pre-wrap text-slate-700">{finding.remediation}</p>
              </div>
            </div>
          )}

          {/* Proof of Concept */}
          {finding.poc && (
            <div className="card p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-slate-900 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-slate-500" />
                  Proof of Concept
                </h3>
                <button
                  onClick={() => copyToClipboard(finding.poc)}
                  className="btn-ghost text-sm"
                >
                  <Copy className="w-4 h-4" />
                  Copy
                </button>
              </div>
              <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg overflow-x-auto text-sm">
                <code>{finding.poc}</code>
              </pre>
            </div>
          )}

          {/* Evidence */}
          {(finding.evidence_items?.length || finding.evidence) && (
            <div className="card p-6">
              <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
                <Image className="w-5 h-5 text-slate-500" />
                Evidence
              </h3>
              <div className="space-y-4">
                {finding.evidence_items?.map((evidence) => (
                  <EvidenceItem key={evidence.id} evidence={evidence} />
                ))}
                {Object.entries(finding.evidence || {}).map(([key, value]) => (
                  <div key={key} className="p-3 bg-slate-50 rounded-lg">
                    <p className="text-sm font-medium text-slate-600">{key}</p>
                    <pre className="text-xs text-slate-500 mt-1 overflow-x-auto">{JSON.stringify(value, null, 2)}</pre>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tags */}
          {finding.tags?.length && (
            <div className="card p-6">
              <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
                <Database className="w-5 h-5 text-slate-500" />
                Tags
              </h3>
              <div className="flex flex-wrap gap-2">
                {finding.tags.map((tag) => (
                  <span key={tag} className="badge bg-slate-100 text-slate-700 border-slate-200">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Metadata */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-slate-900 mb-4">Metadata</h3>
            <dl className="space-y-3 text-sm">
              <div className="flex justify-between">
                <dt className="text-slate-500">ID</dt>
                <dd className="font-mono font-medium text-slate-900">#{finding.id}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500">Program ID</dt>
                <dd className="font-mono font-medium text-slate-900">{finding.program_id}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500">Type</dt>
                <dd className="capitalize text-slate-900">{finding.vuln_type.replace('_', ' ')}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500">Severity</dt>
                <dd>
                  <span className={clsx('badge', severityColors[finding.severity as keyof typeof severityColors])}>
                    {finding.severity}
                  </span>
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-slate-500">Status</dt>
                <dd>
                  <span className={clsx('badge', statusColors[finding.status as keyof typeof statusColors])}>
                    {finding.status.replace('_', ' ')}
                  </span>
                </dd>
              </div>
              {finding.cvss_score && (
                <div className="flex justify-between">
                  <dt className="text-slate-500">CVSS</dt>
                  <dd className="font-mono font-medium text-slate-900">
                    {finding.cvss_score.toFixed(1)} ({finding.cvss_vector})
                  </dd>
                </div>
              )}
              <div className="flex justify-between">
                <dt className="text-slate-500">Created</dt>
                <dd className="text-slate-900">{new Date(finding.created_at).toLocaleString()}</dd>
              </div>
              {finding.validated_at && (
                <div className="flex justify-between">
                  <dt className="text-slate-500">Validated</dt>
                  <dd className="text-slate-900">{new Date(finding.validated_at).toLocaleString()}</dd>
                </div>
              )}
              {finding.reported_at && (
                <div className="flex justify-between">
                  <dt className="text-slate-500">Reported</dt>
                  <dd className="text-slate-900">{new Date(finding.reported_at).toLocaleString()}</dd>
                </div>
              )}
              {finding.duplicate_of && (
                <div className="flex justify-between">
                  <dt className="text-slate-500">Duplicate Of</dt>
                  <dd className="font-mono font-medium text-slate-900">#{finding.duplicate_of}</dd>
                </div>
              )}
            </dl>
          </div>

          {/* Status Actions */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-slate-900 mb-4">Actions</h3>
            <div className="space-y-2">
              {finding.status === 'new' && (
                <button
                  onClick={() => handleStatusChange('validated')}
                  className="btn-primary w-full"
                >
                  <Flag className="w-4 h-4" />
                  Mark as Validated
                </button>
              )}
              {finding.status === 'validated' && (
                <button
                  onClick={handleReport}
                  className="btn-primary w-full"
                >
                  <Globe className="w-4 h-4" />
                  Mark as Reported
                </button>
              )}
              {finding.status !== 'reported' && finding.status !== 'false_positive' && (
                <button
                  onClick={handleDuplicate}
                  className="btn-secondary w-full"
                >
                  <Copy className="w-4 h-4" />
                  Mark as Duplicate
                </button>
              )}
              <button
                onClick={() => handleStatusChange('false_positive')}
                disabled={finding.status === 'false_positive'}
                className="btn-danger w-full"
              >
                <Trash2 className="w-4 h-4" />
                Mark as False Positive
              </button>
            </div>
          </div>

          {/* Download Report */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-slate-900 mb-4">Export Report</h3>
            <div className="space-y-2">
              <button className="btn-secondary w-full justify-start" onClick={() => downloadReport('markdown')}>
                <Download className="w-4 h-4" />
                Markdown (.md)
              </button>
              <button className="btn-secondary w-full justify-start" onClick={() => downloadReport('html')}>
                <Download className="w-4 h-4" />
                HTML (.html)
              </button>
              <button className="btn-secondary w-full justify-start" onClick={() => downloadReport('hackerone')}>
                <Download className="w-4 h-4" />
                HackerOne Format
              </button>
              <button className="btn-secondary w-full justify-start" onClick={() => downloadReport('bugcrowd')>
                <Download className="w-4 h-4" />
                Bugcrowd Format
              </button>
              <button className="btn-secondary w-full justify-start" onClick={() => downloadReport('intigriti')>
                <Download className="w-4 h-4" />
                Intigriti Format
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function EvidenceItem({ evidence }: { evidence: EvidenceItem }) {
  const icons: Record<string, React.ComponentType<{ className?: string }>> = {
    screenshot: Image,
    video: Video,
    har: Database,
    burp: Terminal,
    terminal: Terminal,
    annotated: Image,
  }

  const Icon = icons[evidence.type] || Database

  return (
    <div className="p-3 bg-slate-50 rounded-lg flex items-center gap-3">
      <Icon className="w-5 h-5 text-slate-500" />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-slate-900 truncate">
          {evidence.path.split('/').pop()}
        </p>
        <p className="text-xs text-slate-500">
          {evidence.type} • {new Date(evidence.created_at).toLocaleString()}
        </p>
      </div>
      <a
        href={`/api/evidence/file/${evidence.id}`}
        target="_blank"
        className="text-primary-600 hover:text-primary-700 text-sm"
      >
        View
      </a>
    </div>
  )
}

const downloadReport = async (format: string) => {
  // Would call API to generate and download report
  alert(`Downloading ${format} report...`)
}

const copyToClipboard = (text: string) => {
  navigator.clipboard.writeText(text)
}

const handleStatusChange = (status: string) => {
  // Would call API
}

const handleReport = () => {
  // Would call API
}

import React from 'react'
import { clsx } from 'clsx'