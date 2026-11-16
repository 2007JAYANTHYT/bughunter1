import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useProgramStore } from '../stores/programStore'
import { Plus, Edit, Trash2, ExternalLink, Play, Pause, RotateCcw } from 'lucide-react'
import { Link } from 'react-router-dom'

interface Program {
  id: number
  name: string
  platform: string
  handle: string
  enabled: boolean
  auth_type: string
  created_at: string
}

export function Programs() {
  const { programs, fetchPrograms, setCurrentProgram, createProgram, updateProgram, deleteProgram } = useProgramStore()
  const queryClient = useQueryClient()

  const { data: apiPrograms, isLoading } = useQuery({
    queryKey: ['programs'],
    queryFn: async () => {
      const res = await fetch('/api/programs')
      if (!res.ok) throw new Error('Failed to fetch programs')
      return res.json() as Promise<Program[]>
    },
  })

  const createMutation = useMutation({
    mutationFn: async (program: Omit<Program, 'id' | 'created_at'>) => {
      const res = await fetch('/api/programs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(program),
      })
      if (!res.ok) throw new Error('Failed to create program')
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['programs'] })
      fetchPrograms()
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await fetch(`/api/programs/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('Failed to delete program')
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['programs'] })
      fetchPrograms()
    },
  })

  const handleCreate = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const formData = new FormData(e.currentTarget)
    const program = {
      name: formData.get('name') as string,
      platform: formData.get('platform') as string,
      handle: formData.get('handle') as string,
      auth_type: formData.get('auth_type') as string,
      auth_env_var: formData.get('auth_env_var') as string,
    }
    try {
      await createMutation.mutateAsync(program)
      e.currentTarget.reset()
    } catch (error) {
      alert('Failed to create program')
    }
  }

  const handleDelete = async (id: number) => {
    if (confirm('Delete this program and all associated data?')) {
      try {
        await deleteMutation.mutateAsync(id)
      } catch (error) {
        alert('Failed to delete program')
      }
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Programs</h1>
          <p className="text-slate-500">Manage your bug bounty programs</p>
        </div>
        <button
          className="btn-primary"
          data-modal-target="create-program-modal"
          data-modal-toggle="create-program-modal"
        >
          <Plus className="w-4 h-4" />
          Add Program
        </button>
      </div>

      {/* Programs Table */}
      <div className="card">
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th className="w-12">ID</th>
                <th>Name</th>
                <th className="w-24">Platform</th>
                <th className="w-28">Handle</th>
                <th className="w-20">Status</th>
                <th className="w-20">Auth</th>
                <th className="w-36">Created</th>
                <th className="w-48">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="text-center py-8">
                    <div className="flex items-center justify-center gap-2">
                      <svg className="animate-spin h-5 w-5 text-primary-600" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      Loading programs...
                    </div>
                  </td>
                </tr>
              ) : apiPrograms?.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-12">
                    <div className="flex flex-col items-center gap-4">
                      <svg className="w-12 h-12 text-slate-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                      </svg>
                      <p className="text-slate-500">No programs yet</p>
                      <button
                        className="btn-primary"
                        data-modal-target="create-program-modal"
                        data-modal-toggle="create-program-modal"
                      >
                        Create Your First Program
                      </button>
                    </div>
                  </td>
                </tr>
              ) : (
                apiPrograms?.map((program) => (
                  <tr key={program.id}>
                    <td className="font-mono text-slate-500">#{program.id}</td>
                    <td className="font-medium text-slate-900">{program.name}</td>
                    <td>
                      <span className="badge badge-p4 capitalize">{program.platform}</span>
                    </td>
                    <td className="font-mono text-sm text-slate-600">{program.handle || '-'}</td>
                    <td>
                      <span className={clsx('badge', program.enabled ? 'badge-validated' : 'badge-false_positive')}>
                        {program.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="text-sm text-slate-600 capitalize">{program.auth_type.replace('_', ' ')}</td>
                    <td className="text-sm text-slate-500">
                      {new Date(program.created_at).toLocaleDateString()}
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <Link to={`/programs/${program.id}`} className="btn-ghost p-1" title="View Details">
                          <ExternalLink className="w-4 h-4" />
                        </Link>
                        <Link to={`/programs/${program.id}`} className="btn-ghost p-1" title="Run Recon">
                          <Play className="w-4 h-4" />
                        </Link>
                        <button
                          onClick={() => deleteMutation.mutate(program.id)}
                          disabled={deleteMutation.isPending}
                          className="btn-ghost p-1 text-red-600 hover:text-red-700"
                          title="Delete"
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
      </div>

      {/* Create Program Modal */}
      <div
        id="create-program-modal"
        className="fixed inset-0 z-50 hidden overflow-y-auto"
        role="dialog"
        aria-modal="true"
      >
        <div className="flex min-h-full items-center justify-center p-4">
          <div className="fixed inset-0 bg-black/50" onClick={() => document.getElementById('create-program-modal')?.classList.add('hidden')} />
          <div className="relative w-full max-w-md bg-white rounded-xl shadow-xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-xl font-bold text-slate-900">Create New Program</h2>
              <button
                onClick={() => document.getElementById('create-program-modal')?.classList.add('hidden')}
                className="p-1 rounded-lg hover:bg-slate-100 text-slate-500"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Program Name *</label>
                <input
                  name="name"
                  type="text"
                  required
                  className="input"
                  placeholder="My Bug Bounty Program"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Platform *</label>
                <select name="platform" required className="select">
                  <option value="">Select platform</option>
                  <option value="hackerone">HackerOne</option>
                  <option value="bugcrowd">Bugcrowd</option>
                  <option value="intigriti">Intigriti</option>
                  <option value="yeswehack">YesWeHack</option>
                  <option value="custom">Custom</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Program Handle</label>
                <input
                  name="handle"
                  type="text"
                  className="input"
                  placeholder="program-handle (for API)"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Auth Type</label>
                <select name="auth_type" className="select">
                  <option value="api_token">API Token</option>
                  <option value="cookie">Cookie</option>
                  <option value="header">Custom Header</option>
                  <option value="none">None</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Auth Env Variable</label>
                <input
                  name="auth_env_var"
                  type="text"
                  className="input"
                  placeholder="H1_TOKEN"
                />
              </div>

              <div className="flex gap-3 pt-4">
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="btn-primary flex-1"
                >
                  {createMutation.isPending ? 'Creating...' : 'Create Program'}
                </button>
                <button
                  type="button"
                  onClick={() => document.getElementById('create-program-modal')?.classList.add('hidden')}
                  className="btn-secondary"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  )
}

// Need to import React and clsx
import React from 'react'
import { clsx } from 'clsx'