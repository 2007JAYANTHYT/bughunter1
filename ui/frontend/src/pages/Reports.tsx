import { useProgramStore } from '../stores/programStore'
import { FileText, Download, Globe, Server, Settings, Plus } from 'lucide-react'

export function Reports() {
  const { currentProgram } = useProgramStore()

  const handleGenerate = async (format: string) => {
    if (!currentProgram) return
    try {
      const res = await fetch(`/api/reports/program/${currentProgram.id}`)
      if (res.ok) {
        const blob = await res.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `report_${currentProgram.name}_${format}.md`
        a.click()
      }
    } catch (error) {
      alert('Failed to generate report')
    }
  }

  const handleExport = async (platform: string) => {
    if (!currentProgram) return
    alert(`Exporting to ${platform}... (would call API)`)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Reports</h1>
          <p className="text-slate-500">Generate and export vulnerability reports</p>
        </div>
      </div>

      {!currentProgram && (
        <div className="card p-12 text-center">
          <FileText className="w-12 h-12 text-slate-300 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-slate-900">Select a Program</h2>
          <p className="text-slate-500 mt-2">Choose a program from the sidebar to generate reports</p>
        </div>
      )}

      {currentProgram && (
        <>
          {/* Program Report */}
          <div className="card p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-lg font-semibold text-slate-900 flex items-center gap-2">
                  <FileText className="w-5 h-5 text-slate-500" />
                  Program Summary Report
                </h3>
                <p className="text-slate-500 text-sm mt-1">
                  Complete overview of all findings for {currentProgram.name}
                </p>
              </div>
              <div className="flex gap-2">
                <button onClick={() => handleGenerate('markdown')} className="btn-primary">
                  <Download className="w-4 h-4" />
                  Generate Markdown
                </button>
                <button onClick={() => handleGenerate('html')} className="btn-secondary">
                  <Download className="w-4 h-4" />
                  Generate HTML
                </button>
                <button onClick={() => handleGenerate('pdf')} className="btn-secondary">
                  <Download className="w-4 h-4" />
                  Generate PDF
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
              <div className="p-4 bg-slate-50 rounded-lg">
                <p className="text-slate-500">Includes</p>
                <ul className="list-disc list-inside mt-2 space-y-1 text-slate-700">
                  <li>Executive summary</li>
                  <li>Severity distribution</li>
                  <li>Vulnerability type breakdown</li>
                  <li>Scope coverage metrics</li>
                  <li>All validated findings</li>
                </ul>
              </div>
              <div className="p-4 bg-slate-50 rounded-lg">
                <p className="text-slate-500">Per Finding</p>
                <ul className="list-disc list-inside mt-2 space-y-1 text-slate-700">
                  <li>Description & impact</li>
                  <li>Proof of concept</li>
                  <li>Evidence screenshots</li>
                  <li>Remediation guidance</li>
                  <li>CVSS scoring</li>
                </ul>
              </div>
              <div className="p-4 bg-slate-50 rounded-lg">
                <p className="text-slate-500">Formats</p>
                <ul className="list-disc list-inside mt-2 space-y-1 text-slate-700">
                  <li>Markdown (.md)</li>
                  <li>HTML (.html)</li>
                  <li>PDF (.pdf)</li>
                  <li>JSON (.json)</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Platform Exports */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Globe className="w-5 h-5 text-slate-500" />
              Platform-Specific Exports
            </h3>
            <p className="text-slate-500 mb-4">Export individual findings in platform-required formats</p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <PlatformExportCard
                platform="HackerOne"
                icon={<Server className="w-6 h-6 text-green-600" />}
                color="green"
                formats={['Markdown', 'JSON']}
                onExport={() => handleExport('hackerone')}
              />
              <PlatformExportCard
                platform="Bugcrowd"
                icon={<Server className="w-6 h-6 text-blue-600" />}
                color="blue"
                formats={['Markdown', 'JSON']}
                onExport={() => handleExport('bugcrowd')}
              />
              <PlatformExportCard
                platform="Intigriti"
                icon={<Server className="w-6 h-6 text-purple-600" />}
                color="purple"
                formats={['Markdown', 'JSON']}
                onExport={() => handleExport('intigriti')}
              />
            </div>
          </div>

          {/* Report Templates */}
          <div className="card p-6">
            <h3 className="text-lg font-semibold text-slate-900 mb-4 flex items-center gap-2">
              <Settings className="w-5 h-5 text-slate-500" />
              Report Templates
            </h3>
            <p className="text-slate-500 mb-4">Choose template style for generated reports</p>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              {[
                { id: 'standard', name: 'Standard', desc: 'Full technical report with all sections' },
                { id: 'minimal', name: 'Minimal', desc: 'Concise summary for quick review' },
                { id: 'detailed', name: 'Detailed', desc: 'Comprehensive with root cause analysis' },
                { id: 'executive', name: 'Executive', desc: 'High-level summary for management' },
              ].map(template => (
                <div key={template.id} className="card p-4 border-2 border-slate-200 hover:border-primary-300 transition-colors cursor-pointer">
                  <h4 className="font-semibold text-slate-900">{template.name}</h4>
                  <p className="text-sm text-slate-500 mt-1">{template.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function PlatformExportCard({ platform, icon, color, formats, onExport }: {
  platform: string
  icon: React.ReactNode
  color: string
  formats: string[]
  onExport: () => void
}) {
  const colors = {
    green: 'bg-green-100 text-green-700 border-green-200',
    blue: 'bg-blue-100 text-blue-700 border-blue-200',
    purple: 'bg-purple-100 text-purple-700 border-purple-200',
  }

  return (
    <div className={clsx('card p-5 border-2', colors[color as keyof typeof colors])}>
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={clsx('p-2 rounded-lg', colors[color as keyof typeof colors].replace('bg-', 'bg-').replace('text-', 'text-').replace('border-', 'border-'))}>
            {icon}
          </div>
          <div>
            <h4 className="font-semibold text-slate-900">{platform}</h4>
            <p className="text-sm text-slate-500">Bug bounty platform</p>
          </div>
        </div>
        <span className="badge bg-slate-100 text-slate-700">Ready</span>
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        {formats.map(f => (
          <span key={f} className="badge bg-white text-slate-700 border-slate-200">
            {f}
          </span>
        ))}
      </div>

      <button onClick={onExport} className={clsx('btn-primary w-full', colors[color as keyof typeof colors].replace('bg-', 'bg-').replace('text-', 'text-').replace('border-', 'border-'))}>
        Export to {platform}
      </button>
    </div>
  )
}

import React from 'react'
import { clsx } from 'clsx'