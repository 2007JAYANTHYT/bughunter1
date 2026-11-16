import { NavLink, useLocation } from 'react-router-dom'
import { useProgramStore } from '../stores/programStore'
import {
  LayoutDashboard,
  FolderKanban,
  Bug,
  ListChecks,
  FileText,
  Settings,
  Plus,
  ChevronRight,
} from 'lucide-react'
import { clsx } from 'clsx'

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Programs', href: '/programs', icon: FolderKanban },
  { name: 'Findings', href: '/findings', icon: Bug },
  { name: 'Scope Checklist', href: '/programs/:id/scope', icon: ListChecks, requiresProgram: true },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Settings', href: '/settings', icon: Settings },
]

export function Sidebar() {
  const location = useLocation()
  const { programs, currentProgram, fetchPrograms } = useProgramStore()

  // Fetch programs on mount
  React.useEffect(() => {
    fetchPrograms()
  }, [fetchPrograms])

  return (
    <aside className="w-72 bg-white border-r border-slate-200 flex flex-col h-screen sticky top-0">
      <div className="p-4 border-b border-slate-200">
        <h1 className="flex items-center gap-2 text-xl font-bold text-slate-900">
          <Bug className="w-6 h-6 text-primary-600" />
          Bug Hunter
        </h1>
        <p className="text-xs text-slate-500 mt-1">Agent v1.0</p>
      </div>

      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {navigation.map((item) => {
          const requiresProgram = item.requiresProgram && !currentProgram
          const isActive = location.pathname === item.href ||
            (item.href !== '/' && location.pathname.startsWith(item.href.replace(':id', String(currentProgram?.id || ''))))

          return (
            <NavLink
              key={item.name}
              to={item.href.replace(':id', String(currentProgram?.id || ''))}
              className={clsx(
                'sidebar-link',
                isActive && 'sidebar-link-active',
                requiresProgram && 'opacity-50 pointer-events-none'
              )}
              disabled={requiresProgram}
              title={requiresProgram ? 'Select a program first' : undefined}
            >
              <item.icon className="w-5 h-5 flex-shrink-0" />
              {item.name}
            </NavLink>
          )
        })}

        {currentProgram && (
          <div className="pt-4 border-t border-slate-200">
            <p className="px-3 text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
              Current Program
            </p>
            <div className="bg-primary-50 rounded-lg p-3">
              <p className="font-medium text-primary-700">{currentProgram.name}</p>
              <p className="text-xs text-primary-500">{currentProgram.platform}</p>
            </div>
          </div>
        )}
      </nav>

      <div className="p-3 border-t border-slate-200">
        <button
          onClick={() => window.location.href = '/programs'}
          className="w-full btn-secondary justify-center"
        >
          <Plus className="w-4 h-4" />
          Add Program
        </button>
      </div>
    </aside>
  )
}

// Need to import React
import React from 'react'