import { Routes, Route, Navigate } from 'react-router-dom'
import { Sidebar } from './components/Sidebar'
import { Header } from './components/Header'
import { Dashboard } from './pages/Dashboard'
import { Programs } from './pages/Programs'
import { ProgramDetail } from './pages/ProgramDetail'
import { Findings } from './pages/Findings'
import { FindingDetail } from './pages/FindingDetail'
import { ScopeChecklist } from './pages/ScopeChecklist'
import { Reports } from './pages/Reports'
import { Settings } from './pages/Settings'
import { useProgramStore } from './stores/programStore'
import { useAuthStore } from './stores/authStore'

function Layout() {
  const { currentProgram } = useProgramStore()
  const { isAuthenticated } = useAuthStore()

  return (
    <div className="min-h-screen bg-slate-50 flex">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <Header />
        <main className="flex-1 p-6 overflow-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/programs" element={<Programs />} />
            <Route path="/programs/:id" element={<ProgramDetail />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/:id" element={<FindingDetail />} />
            <Route path="/programs/:id/scope" element={<ScopeChecklist />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return <Layout />
}