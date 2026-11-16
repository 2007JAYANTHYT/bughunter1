import { useQuery } from '@tanstack/react-query'
import { useProgramStore } from '../stores/programStore'
import { Link } from 'react-router-dom'
import { Bug, Target, CheckCircle, Clock, TrendingUp, AlertTriangle } from 'lucide-react'
import { clsx } from 'clsx'

interface Stats {
  total_programs: number
  total_findings: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_type: Record<string, number>
}

interface Finding {
  id: number
  program_id: number
  vuln_type: string
  severity: string
  title: string
  status: string
  created_at: string
}

export function Dashboard() {
  const { currentProgram } = useProgramStore()

  const { data: globalStats } = useQuery({
    queryKey: ['stats'],
    queryFn: async () => {
      const res = await fetch('/api/stats')
      if (!res.ok) throw new Error('Failed to fetch stats')
      return res.json() as Promise<Stats>
    },
  })

  const { data: programStats } = useQuery({
    queryKey: ['stats', currentProgram?.id],
    enabled: !!currentProgram,
    queryFn: async () => {
      const res = await fetch(`/api/stats/${currentProgram!.id}`)
      if (!res.ok) throw new Error('Failed to fetch program stats')
      return res.json() as Promise<Stats>
    },
  })

  const { data: recentFindings } = useQuery({
    queryKey: ['findings', 'recent', currentProgram?.id],
    queryFn: async () => {
      const programId = currentProgram?.id || ''
      const res = await fetch(`/api/findings${programId ? `?program_id=${programId}` : ''}&limit=5`)
      if (!res.ok) throw new Error('Failed to fetch findings')
      return res.json() as Promise<Finding[]>
    },
  })

  const stats = currentProgram ? programStats : globalStats

  const severityColors = {
    P1: 'text-severity-p1',
    P2: 'text-severity-p2',
    P3: 'text-severity-p3',
    P4: 'text-severity-p4',
  }

  const statusColors = {
    new: 'text-status-new',
    validated: 'text-status-validated',
    reported: 'text-status-reported',
    duplicate: 'text-status-duplicate',
    false_positive: 'text-status-false_positive',
    fixed: 'text-status-fixed',
    paid: 'text-status-paid',
  }

  if (!currentProgram && !globalStats) {
    return (
      <div className="text-center py-12">
        <Bug className="w-12 h-12 text-slate-300 mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-slate-900">Welcome to Bug Hunter Agent</h2>
        <p className="text-slate-500 mt-2">Create a program to get started</p>
        <Link to="/programs" className="btn-primary mt-4 inline-flex">
          Create Program
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">
            {currentProgram ? currentProgram.name : 'Global'} Dashboard
          </h1>
          <p className="text-slate-500">
            {currentProgram
              ? `Monitoring ${currentProgram.platform} program`
              : 'Overview of all programs'}
          </p>
        </div>
        <Link to={currentProgram ? `/programs/${currentProgram.id}` : '/programs'} className="btn-primary">
          View Program
        </Link>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="Total Programs"
          value={globalStats?.total_programs || 0}
          icon={Target}
          color="primary"
          link="/programs"
        />
        <StatCard
          title="Total Findings"
          value={stats?.total_findings || 0}
          icon={Bug}
          color="orange"
          link="/findings"
        />
        <StatCard
          title="Critical (P1)"
          value={stats?.by_severity?.P1 || 0}
          icon={AlertTriangle}
          color="red"
          severity="P1"
        />
        <StatCard
          title="High (P2)"
          value={stats?.by_severity?.P2 || 0}
          icon={AlertTriangle}
          color="amber"
          severity="P2"
        />
        <StatCard
          title="Validated"
          value={stats?.by_status?.validated || 0}
          icon={CheckCircle}
          color="green"
        />
      </div>

      {/* Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card p-6">
          <h3 className="text-lg font-semibold text-slate-900 mb-4">Severity Distribution</h3>
          <div className="space-y-3">
            {(['P1', 'P2', 'P3', 'P4'] as const).map((sev) => (
              <SeverityBar
                key={sev}
                label={sev}
                value={stats?.by_severity?.[sev] || 0}
                total={stats?.total_findings || 1}
                color={severityColors[sev].replace('text-', 'bg-')}
              />
            ))}
          </div>
        </div>

        <div className="card p-6">
          <h3 className="text-lg font-semibold text-slate-900 mb-4">Status Distribution</h3>
          <div className="space-y-3">
            {(Object.entries(stats?.by_status || {}) as [string, number][]).map(([status, value]) => (
              <StatusBar
                key={status}
                label={status}
                value={value}
                total={stats?.total_findings || 1}
                color={statusColors[status as keyof typeof statusColors]?.replace('text-', 'bg-') || 'bg-slate-500'}
              />
            ))}
          </div>
        </div>
      </div>

      {/* Recent Findings */}
      <div className="card">
        <div className="p-4 border-b border-slate-200 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-slate-900">Recent Findings</h3>
          <Link to="/findings" className="text-sm text-primary-600 hover:text-primary-700">
            View All
          </Link>
        </div>
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th className="w-12">ID</th>
                <th>Title</th>
                <th className="w-24">Type</th>
                <th className="w-24">Severity</th>
                <th className="w-28">Status</th>
                <th className="w-36">Created</th>
                <th className="w-12"></th>
              </tr>
            </thead>
            <tbody>
              {recentFindings?.map((finding) => (
                <tr key={finding.id}>
                  <td className="font-mono text-slate-500">#{finding.id}</td>
                  <td className="font-medium text-slate-900 max-w-xs truncate">{finding.title}</td>
                  <td className="text-slate-600 capitalize">{finding.vuln_type.replace('_', ' ')}</td>
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
                  <td className="text-slate-500 text-sm">
                    {new Date(finding.created_at).toLocaleDateString()}
                  </td>
                  <td>
                    <Link to={`/findings/${finding.id}`} className="text-primary-600 hover:text-primary-700">
                      View
                    </Link>
                  </td>
                </tr>
              ))}
              {(!recentFindings || recentFindings.length === 0) && (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-slate-500">
                    No findings yet. Start a hunt to discover vulnerabilities.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Top Vulnerability Types */}
      <div className="card p-6">
        <h3 className="text-lg font-semibold text-slate-900 mb-4">Top Vulnerability Types</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {(Object.entries(stats?.by_type || {})
            .sort(([, a], [, b]) => b - a)
            .slice(0, 8)
            .map(([type, count]) => (
              <div key={type} className="p-4 bg-slate-50 rounded-lg">
                <p className="text-sm text-slate-500">{type.replace('_', ' ')}</p>
                <p className="text-2xl font-bold text-slate-900">{count}</p>
              </div>
            ))}
        </div>
      </div>
    </div>
  )
}

function StatCard({
  title,
  value,
  icon: Icon,
  color,
  severity,
  link,
}: {
  title: string
  value: number
  icon: React.ComponentType<{ className?: string }>
  color: string
  severity?: string
  link?: string
}) {
  const colors = {
    primary: 'bg-primary-100 text-primary-700',
    orange: 'bg-orange-100 text-orange-700',
    red: 'bg-red-100 text-red-700',
    amber: 'bg-amber-100 text-amber-700',
    green: 'bg-green-100 text-green-700',
  }

  return (
    <Link to={link || '#'} className="card p-5 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-slate-500">{title}</p>
          <p className="text-3xl font-bold text-slate-900 mt-1">{value.toLocaleString()}</p>
        </div>
        <div className={clsx('p-3 rounded-xl', colors[color as keyof typeof colors] || colors.primary)}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </Link>
  )
}

function SeverityBar({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const percentage = total > 0 ? (value / total) * 100 : 0

  return (
    <div className="flex items-center gap-3">
      <span className="w-12 text-sm font-medium text-slate-600">{label}</span>
      <div className="flex-1 h-2 bg-slate-200 rounded-full overflow-hidden">
        <div
          className={clsx('h-full rounded-full transition-all duration-500', color)}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span className="w-16 text-sm text-slate-500 text-right">{value} ({percentage.toFixed(1)}%)</span>
    </div>
  )
}

function StatusBar({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const percentage = total > 0 ? (value / total) * 100 : 0

  return (
    <div className="flex items-center gap-3">
      <span className="w-24 text-sm text-slate-600 capitalize">{label.replace('_', ' ')}</span>
      <div className="flex-1 h-2 bg-slate-200 rounded-full overflow-hidden">
        <div
          className={clsx('h-full rounded-full transition-all duration-500', color)}
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span className="w-16 text-sm text-slate-500 text-right">{value} ({percentage.toFixed(1)}%)</span>
    </div>
  )
}