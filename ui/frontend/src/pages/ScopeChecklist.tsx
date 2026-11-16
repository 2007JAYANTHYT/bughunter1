import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useProgramStore } from '../stores/programStore'
import { CheckCircle, Clock, XCircle, MinusCircle, Play, RefreshCw, Download, Filter, ChevronDown, ChevronUp } from 'lucide-react'
import { clsx } from 'clsx'

interface ScopeItem {
  id: number
  item_type: string
  pattern: string
  description: string
  status: string
  tested_at: string | null
  notes: string
  findings_count: number
  critical_findings: number
  high_findings: number
  pattern_type: string
}

interface CoverageMetrics {
  program_id: number
  total_in_scope: number
  total_out_of_scope: number
  tested_in_scope: number
  tested_out_of_scope: number
  skipped_in_scope: number
  skipped_out_of_scope: number
  pending_in_scope: number
  pending_out_of_scope: number
  coverage_percentage: number
  findings_total: number
  critical_high_findings: number
  last_updated: string
}

interface ProgressData {
  metrics: CoverageMetrics
  by_type: Record<string, { total: number; tested: number; pending: number; skipped: number; progress: number }>
  items: ScopeItem[]
}

export function ScopeChecklist() {
  const { id } = useParams<{ id: string }>()
  const { currentProgram } = useProgramStore()
  const queryClient = useQueryClient()

  const programId = parseInt(id || '0')

  const { data: progress, isLoading } = useQuery({
    queryKey: ['scope', 'progress', programId],
    queryFn: async () => {
      const res = await fetch(`/api/scope/${programId}/coverage`)
      if (!res.ok) throw new Error('Failed to fetch scope progress')
      return res.json() as Promise<ProgressData>
    },
    enabled: !!programId,
  })

  const { data: checklist } = useQuery({
    queryKey: ['scope', 'checklist', programId],
    queryFn: async () => {
      const res = await fetch(`/api/scope/${programId}`)
      if (!res.ok) throw new Error('Failed to fetch checklist')
      return res.json() as Promise<ScopeItem[]>
    },
    enabled: !!programId,
  })

  const updateMutation = useMutation({
    mutationFn: async ({ itemId, status, notes }: { itemId: number; status: string; notes?: string }) => {
      const res = await fetch(`/api/scope/${programId}/items/${itemId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, notes }),
      })
      if (!res.ok) throw new Error('Failed to update scope item')
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scope', 'checklist', programId] })
      queryClient.invalidateQueries({ queryKey: ['scope', 'progress', programId] })
    },
  })

  const generateMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch(`/api/scope/${programId}/generate`, { method: 'POST' })
      if (!res.ok) throw new Error('Failed to generate checklist')
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scope', 'checklist', programId] })
      queryClient.invalidateQueries({ queryKey: ['scope', 'progress', programId] })
    },
  })

  const handleStatusChange = (itemId: number, status: string) => {
    updateMutation.mutate({ itemId, status })
  }

  const handleStartTesting = (itemId: number) => {
    handleStatusChange(itemId, 'testing')
  }

  const handleMarkTested = (itemId: number) => {
    handleStatusChange(itemId, 'tested')
  }

  const handleSkip = (itemId: number) => {
    const reason = prompt('Reason for skipping:')
    if (reason) {
      handleStatusChange(itemId, 'skipped', `Skipped: ${reason}`)
    }
  }

  const [filter, setFilter] = React.useState<'all' | 'in_scope' | 'out_of_scope' | 'pending' | 'testing' | 'tested' | 'skipped'>('all')
  const [expandedTypes, setExpandedTypes] = React.useState<Record<string, boolean>>({})

  const filteredItems = React.useMemo(() => {
    if (!checklist) return []
    return checklist.filter(item => {
      if (filter === 'all') return true
      if (filter === 'in_scope') return item.item_type === 'in_scope'
      if (filter === 'out_of_scope') return item.item_type === 'out_of_scope'
      return item.status === filter
    })
  }, [checklist, filter])

  const groupedItems = React.useMemo(() => {
    const groups: Record<string, ScopeItem[]> = {}
    filteredItems.forEach(item => {
      const key = item.pattern_type
      if (!groups[key]) groups[key] = []
      groups[key].push(item)
    })
    return groups
  }, [filteredItems])

  if (!currentProgram || programId !== currentProgram.id) {
    return (
      <div className="text-center py-12">
        <h2 className="text-xl font-semibold text-slate-900">Select a program</h2>
        <p className="text-slate-500 mt-2">Choose a program from the sidebar to view its scope checklist</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Scope Checklist</h1>
          <p className="text-slate-500">{currentProgram.name} - {currentProgram.platform}</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => generateMutation.mutate()}
            disabled={generateMutation.isPending}
            className="btn-secondary"
          >
            <RefreshCw className={clsx('w-4 h-4', generateMutation.isPending && 'animate-spin')} />
            Generate Checklist
          </button>
          <button className="btn-secondary" onClick={() => window.open(`/api/scope/${programId}/export?format=markdown`, '_blank')}>
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </div>

      {/* Coverage Metrics */}
      {progress && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <MetricCard
            title="Coverage"
            value={`${progress.metrics.coverage_percentage.toFixed(1)}%`}
            icon={<CheckCircle className="w-5 h-5" />}
            color="green"
            subtitle={`${progress.metrics.tested_in_scope + progress.metrics.skipped_in_scope} / ${progress.metrics.total_in_scope} in-scope`}
          />
          <MetricCard
            title="In-Scope Tested"
            value={progress.metrics.tested_in_scope}
            icon={<CheckCircle className="w-5 h-5" />}
            color="blue"
            subtitle={`${progress.metrics.pending_in_scope} pending, ${progress.metrics.skipped_in_scope} skipped`}
          />
          <MetricCard
            title="Findings"
            value={progress.metrics.findings_total}
            icon={<AlertTriangle className="w-5 h-5" />}
            color="orange"
            subtitle={`${progress.metrics.critical_high_findings} critical/high`}
          />
          <MetricCard
            title="Out-of-Scope"
            value={progress.metrics.total_out_of_scope}
            icon={<XCircle className="w-5 h-5" />}
            color="gray"
            subtitle={`${progress.metrics.tested_out_of_scope} tested, ${progress.metrics.skipped_out_of_scope} skipped`}
          />
        </div>
      )}

      {/* Filters */}
      <div className="card p-4">
        <div className="flex flex-wrap items-center gap-4">
          <Filter className="w-5 h-5 text-slate-500" />
          <div className="flex gap-2" role="radiogroup">
            {[
              { value: 'all', label: 'All' },
              { value: 'in_scope', label: 'In-Scope' },
              { value: 'out_of_scope', label: 'Out-of-Scope' },
              { value: 'pending', label: 'Pending' },
              { value: 'testing', label: 'Testing' },
              { value: 'tested', label: 'Tested' },
              { value: 'skipped', label: 'Skipped' },
            ].map(({ value, label }) => (
              <button
                key={value}
                onClick={() => setFilter(value)}
                className={clsx(
                  'px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
                  filter === value
                    ? 'bg-primary-100 text-primary-700'
                    : 'text-slate-600 hover:bg-slate-100'
                )}
                role="radio"
                aria-checked={filter === value}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Checklist */}
      <div className="card">
        {isLoading ? (
          <div className="p-8 text-center">
            <svg className="animate-spin h-8 w-8 text-primary-600 mx-auto mb-4" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            <p className="text-slate-500">Loading checklist...</p>
          </div>
        ) : Object.keys(groupedItems).length === 0 ? (
          <div className="p-8 text-center">
            <CheckCircle className="w-12 h-12 text-slate-300 mx-auto mb-4" />
            <p className="text-slate-500">No scope items match the current filter</p>
            <button onClick={() => generateMutation.mutate()} className="btn-primary mt-4">
              Generate Checklist
            </button>
          </div>
        ) : (
          <>
            {Object.entries(groupedItems).map(([type, items]) => (
              <ScopeTypeSection
                key={type}
                type={type}
                items={items}
                expanded={expandedTypes[type] || false}
                onToggle={() => setExpandedTypes(prev => ({ ...prev, [type]: !prev[type] }))}
                onStatusChange={handleStatusChange}
                onStartTesting={handleStartTesting}
                onMarkTested={handleMarkTested}
                onSkip={handleSkip}
                progress={progress?.by_type?.[type]}
              />
            ))}
          </>
        )}

        {/* Progress by Type */}
        {progress && (
          <div className="border-t border-slate-200 p-4">
            <h3 className="text-lg font-semibold text-slate-900 mb-4">Progress by Type</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Object.entries(progress.by_type).map(([type, stats]) => (
                <TypeProgressCard key={type} type={type} stats={stats} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function MetricCard({ title, value, icon, color, subtitle }: { title: string; value: string; icon: React.ReactNode; color: string; subtitle: string }) {
  const colors = {
    green: 'bg-green-100 text-green-700',
    blue: 'bg-blue-100 text-blue-700',
    orange: 'bg-orange-100 text-orange-700',
    red: 'bg-red-100 text-red-700',
    gray: 'bg-slate-100 text-slate-700',
  }

  return (
    <div className="card p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-slate-500">{title}</p>
          <p className="text-3xl font-bold text-slate-900 mt-1">{value}</p>
          <p className="text-xs text-slate-500 mt-1">{subtitle}</p>
        </div>
        <div className={clsx('p-3 rounded-xl', colors[color as keyof typeof colors] || colors.gray)}>
          {icon}
        </div>
      </div>
    </div>
  )
}

function ScopeTypeSection({
  type,
  items,
  expanded,
  onToggle,
  onStatusChange,
  onStartTesting,
  onMarkTested,
  onSkip,
  progress,
}: {
  type: string
  items: ScopeItem[]
  expanded: boolean
  onToggle: () => void
  onStatusChange: (id: number, status: string) => void
  onStartTesting: (id: number) => void
  onMarkTested: (id: number) => void
  onSkip: (id: number) => void
  progress?: { total: number; tested: number; pending: number; skipped: number; progress: number }
}) {
  const statusIcons = {
    pending: <Clock className="w-4 h-4 text-slate-400" />,
    testing: <Play className="w-4 h-4 text-blue-600 animate-pulse" />,
    tested: <CheckCircle className="w-4 h-4 text-green-600" />,
    skipped: <MinusCircle className="w-4 h-4 text-slate-400" />,
  }

  const statusColors = {
    pending: 'badge-new bg-blue-100 text-blue-800',
    testing: 'badge-testing bg-blue-100 text-blue-800 animate-pulse',
    tested: 'badge-validated bg-green-100 text-green-800',
    skipped: 'badge-skipped bg-slate-100 text-slate-800',
  }

  return (
    <div className="border-b border-slate-200 last:border-0">
      <button
        onClick={onToggle}
        className="w-full p-4 flex items-center justify-between hover:bg-slate-50 transition-colors"
      >
        <div className="flex items-center gap-4">
          <span className={clsx('font-medium text-slate-900 capitalize', expanded && 'text-primary-600')}>
            {type.replace('_', ' ')}
          </span>
          {progress && (
            <span className="badge bg-slate-100 text-slate-700">
              {stats.tested + stats.skipped}/{stats.total} ({progress.toFixed(1)}%)
            )}
          }
          <span className={clsx('badge', statusColors['pending'])}>
            {items.filter(i => i.status === 'pending').length}
          </span>
          <span className={clsx('badge', statusColors['testing'])}>
            {items.filter(i => i.status === 'testing').length}
          </span>
          <span className={clsx('badge', statusColors['tested'])}>
            {items.filter(i => i.status === 'tested').length}
          </span>
          <span className={clsx('badge', statusColors['skipped'])}>
            {items.filter(i => i.status === 'skipped').length}
          </span>
        </div>
        <ChevronDown className={clsx('w-5 h-5 text-slate-500 transition-transform', expanded && 'rotate-180')} />
      </button>

      {expanded && (
        <div className="divide-y divide-slate-100 bg-slate-50">
          {items.map(item => (
            <ScopeItemRow
              key={item.id}
              item={item}
              statusIcon={statusIcons[item.status as keyof typeof statusIcons]}
              statusColor={statusColors[item.status as keyof typeof statusColors]}
              onStatusChange={onStatusChange}
              onStartTesting={onStartTesting}
              onMarkTested={onMarkTested}
              onSkip={onSkip}
            />
          ))}
        </div>
      )}
    </div>
  )
}

const stats = { total: 0, tested: 0, pending: 0, skipped: 0 }

function ScopeItemRow({
  item,
  statusIcon,
  statusColor,
  onStatusChange,
  onStartTesting,
  onMarkTested,
  onSkip,
}: {
  item: ScopeItem
  statusIcon: React.ReactNode
  statusColor: string
  onStatusChange: (id: number, status: string) => void
  onStartTesting: (id: number) => void
  onMarkTested: (id: number) => void
  onSkip: (id: number) => void
}) {
  const typeBadge = item.item_type === 'in_scope'
    ? <span className="badge bg-green-100 text-green-800">In-Scope</span>
    : <span className="badge bg-red-100 text-red-800">Out-of-Scope</span>

  return (
    <div className="p-4 hover:bg-white transition-colors flex items-center gap-4">
      <div className="w-10 flex-shrink-0">{statusIcon}</div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <code className="font-mono text-sm text-slate-900 truncate max-w-md">{item.pattern}</code>
          {typeBadge}
          <span className="badge bg-slate-100 text-slate-700">{item.pattern_type}</span>
        </div>
        {item.description && (
          <p className="text-sm text-slate-500 mt-1 truncate max-w-2xl">{item.description}</p>
        )}
        {item.notes && (
          <p className="text-xs text-slate-400 mt-1 italic">Notes: {item.notes}</p>
        )}
        {item.findings_count > 0 && (
          <div className="flex items-center gap-2 mt-1">
            <span className="badge bg-red-100 text-red-800">{item.critical_findings} Critical</span>
            <span className="badge bg-orange-100 text-orange-800">{item.high_findings} High</span>
            <span className="badge bg-slate-100 text-slate-700">{item.findings_count - item.critical_findings - item.high_findings} Other</span>
          </div>
        )}
      </div>
      <div className="flex items-center gap-2">
        <span className={clsx('badge w-24', statusColor)}>{item.status}</span>
        <div className="flex items-center gap-1">
          {item.status === 'pending' && (
            <>
              <button onClick={() => onStartTesting(item.id)} className="p-1.5 rounded hover:bg-slate-200 text-blue-600" title="Start Testing">
                <Play className="w-4 h-4" />
              </button>
              <button onClick={() => onMarkTested(item.id)} className="p-1.5 rounded hover:bg-slate-200 text-green-600" title="Mark Tested">
                <CheckCircle className="w-4 h-4" />
              </button>
              <button onClick={() => onSkip(item.id)} className="p-1.5 rounded hover:bg-slate-200 text-slate-600" title="Skip">
                <MinusCircle className="w-4 h-4" />
              </button>
            </>
          )}
          {item.status === 'testing' && (
            <>
              <button onClick={() => onMarkTested(item.id)} className="p-1.5 rounded hover:bg-slate-200 text-green-600" title="Mark Tested">
                <CheckCircle className="w-4 h-4" />
              </button>
              <button onClick={() => onSkip(item.id)} className="p-1.5 rounded hover:bg-slate-200 text-slate-600" title="Skip">
                <MinusCircle className="w-4 h-4" />
              </button>
            </>
          )}
          {item.status === 'tested' && (
            <button onClick={() => onStatusChange(item.id, 'pending')} className="p-1.5 rounded hover:bg-slate-200 text-slate-600" title="Reset to Pending">
              <RefreshCw className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function TypeProgressCard({ type, stats }: { type: string; stats: { total: number; tested: number; pending: number; skipped: number; progress: number } }) {
  const tested = stats.tested + stats.skipped
  const color = stats.progress === 100 ? 'green' : stats.progress > 50 ? 'blue' : stats.progress > 0 ? 'amber' : 'gray'

  const colors = {
    green: 'bg-green-500',
    blue: 'bg-blue-500',
    amber: 'bg-amber-500',
    gray: 'bg-slate-400',
  }

  return (
    <div className="card p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="font-medium text-slate-900 capitalize">{type.replace('_', ' ')}</span>
        <span className="text-2xl font-bold text-slate-900">{stats.progress.toFixed(1)}%</span>
      </div>
      <div className="h-2 bg-slate-200 rounded-full overflow-hidden">
        <div
          className={clsx('h-full rounded-full transition-all duration-500', colors[color as keyof typeof colors])}
          style={{ width: `${stats.progress}%` }}
        />
      </div>
      <div className="flex items-center justify-between text-xs text-slate-500 mt-2">
        <span>Tested: {stats.tested}</span>
        <span>Skipped: {stats.skipped}</span>
        <span>Pending: {stats.pending}</span>
        <span>Total: {stats.total}</span>
      </div>
    </div>
  )
}

import React from 'react'
import { AlertTriangle, ChevronDown, RefreshCw } from 'lucide-react'
import { clsx } from 'clsx'