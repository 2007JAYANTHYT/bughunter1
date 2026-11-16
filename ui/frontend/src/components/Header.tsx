import { useProgramStore } from '../stores/programStore'
import { Search, Bell, User, LogOut, Menu } from 'lucide-react'
import { useAuthStore } from '../stores/authStore'

export function Header() {
  const { currentProgram } = useProgramStore()
  const { isAuthenticated, user, logout } = useAuthStore()

  return (
    <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-6 sticky top-0 z-10">
      <div className="flex items-center gap-4">
        <h2 className="text-lg font-semibold text-slate-900">
          {currentProgram ? currentProgram.name : 'Select a program'}
        </h2>
        {currentProgram && (
          <span className="badge badge-p4 capitalize">{currentProgram.platform}</span>
        )}
      </div>

      <div className="flex items-center gap-4">
        <div className="relative hidden md:block">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search findings, programs..."
            className="input pl-10 w-64"
          />
        </div>

        <button className="relative p-2 rounded-lg hover:bg-slate-100 transition-colors">
          <Bell className="w-5 h-5 text-slate-600" />
          <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full" />
        </button>

        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-primary-100 flex items-center justify-center">
            <User className="w-4 h-4 text-primary-600" />
          </div>
          <div className="hidden sm:block text-right">
            <p className="text-sm font-medium text-slate-900">{user?.name || 'User'}</p>
            <p className="text-xs text-slate-500">{user?.email || 'user@example.com'}</p>
          </div>
          <button
            onClick={logout}
            className="p-2 rounded-lg hover:bg-slate-100 transition-colors text-slate-500"
            title="Logout"
          >
            <LogOut className="w-5 h-5" />
          </button>
        </div>
      </div>
    </header>
  )
}