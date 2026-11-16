import { useProgramStore } from '../stores/programStore'
import { Settings, Cpu, Shield, Database, Terminal, Globe, Key, Bell, Palette, Trash2 } from 'lucide-react'
import { clsx } from 'clsx'

export function Settings() {
  const { programs, fetchPrograms } = useProgramStore()

  const [activeTab, setActiveTab] = React.useState<'general' | 'hunting' | 'validation' | 'ai' | 'notifications' | 'advanced'>('general')
  const [config, setConfig] = React.useState({
    hunting: {
      threads: 50,
      timeout: 30,
      rate_limit_rps: 10,
      strict_scope: true,
      nuclei_enabled: true,
      dalfox_enabled: true,
      sqlmap_enabled: true,
      ai_hunting_enabled: true,
    },
    validation: {
      browser_headless: false,
      burp_enabled: true,
      mitmproxy_fallback: true,
      ai_validation_enabled: true,
      confidence_threshold: 0.8,
    },
    ai: {
      primary_model: 'llama3.1:70b',
      code_model: 'deepseek-coder:33b',
      reasoning_model: 'nemotron3-ultra',
      fast_model: 'phi3:14b',
    },
    notifications: {
      webhook_url: '',
      email: '',
      on_critical: true,
      on_high: true,
      on_validated: false,
    },
  })

  const tabs = [
    { id: 'general', label: 'General', icon: Settings },
    { id: 'hunting', label: 'Hunting', icon: Cpu },
    { id: 'validation', label: 'Validation', icon: Shield },
    { id: 'ai', label: 'AI Models', icon: Database },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'advanced', label: 'Advanced', icon: Terminal },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Settings</h1>
          <p className="text-slate-500">Configure Bug Hunter Agent behavior</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="card">
        <div className="border-b border-slate-200">
          <nav className="flex overflow-x-auto" aria-label="Settings tabs">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
                  activeTab === tab.id
                    ? 'border-primary-600 text-primary-600'
                    : 'border-transparent text-slate-500 hover:text-slate-700 hover:border-slate-300'
                )}
                role="tab"
                aria-selected={activeTab === tab.id}
              >
                <tab.icon className="w-4 h-4 mr-2 inline-block" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {activeTab === 'general' && <GeneralSettings />}
          {activeTab === 'hunting' && <HuntingSettings config={config.hunting} onChange={(c) => setConfig(prev => ({ ...prev, hunting: c }))} />}
          {activeTab === 'validation' && <ValidationSettings config={config.validation} onChange={(c) => setConfig(prev => ({ ...prev, validation: c }))} />}
          {activeTab === 'ai' && <AISettings config={config.ai} onChange={(c) => setConfig(prev => ({ ...prev, ai: c }))} />}
          {activeTab === 'notifications' && <NotificationSettings config={config.notifications} onChange={(c) => setConfig(prev => ({ ...prev, notifications: c }))} />}
          {activeTab === 'advanced' && <AdvancedSettings />}
        </div>
      </div>

      {/* Danger Zone */}
      <div className="card border-red-200">
        <div className="p-6 border-b border-red-200 flex items-center gap-3">
          <Trash2 className="w-6 h-6 text-red-600" />
          <h3 className="text-lg font-semibold text-red-700">Danger Zone</h3>
        </div>
        <div className="p-6 space-y-4">
          <div className="flex items-center justify-between p-4 bg-red-50 rounded-lg border border-red-200">
            <div>
              <p className="font-medium text-red-800">Reset All Data</p>
              <p className="text-sm text-red-600">This will delete all programs, findings, and evidence. This action cannot be undone.</p>
            </div>
            <button className="btn-danger">Reset Everything</button>
          </div>

          <div className="flex items-center justify-between p-4 bg-red-50 rounded-lg border border-red-200">
            <div>
              <p className="font-medium text-red-800">Clear Evidence Files</p>
              <p className="text-sm text-red-600">Delete all screenshots, videos, HAR files, and terminal recordings. Findings will be preserved.</p>
            </div>
            <button className="btn-secondary text-red-600 hover:bg-red-50">Clear Evidence</button>
          </div>
        </div>
      </div>
    </div>
  )
}

function GeneralSettings() {
  const [settings, setSettings] = React.useState({
    theme: 'light',
    language: 'en',
    auto_save: true,
    compact_mode: false,
    show_severity_colors: true,
  })

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h4 className="font-medium text-slate-900 mb-4">Appearance</h4>
        <div className="space-y-4">
          <SettingRow
            label="Theme"
            description="Choose color theme"
          >
            <select
              value={settings.theme}
              onChange={(e) => setSettings(prev => ({ ...prev, theme: e.target.value }))}
              className="select w-48"
            >
              <option value="light">Light</option>
              <option value="dark">Dark</option>
              <option value="system">System</option>
            </select>
          </SettingRow>

          <SettingRow
            label="Language"
            description="Interface language"
          >
            <select className="select w-48">
              <option value="en">English</option>
              <option value="es">Spanish</option>
              <option value="fr">French</option>
            </select>
          </SettingRow>

          <SettingToggle
            label="Compact Mode"
            description="Reduce padding and spacing for dense view"
            checked={false}
            onChange={() => {}}
          />

          <SettingToggle
            label="Show Severity Colors"
            description="Color-code findings by severity"
            checked={true}
            onChange={() => {}}
          />
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">Behavior</h4>
        <div className="space-y-4">
          <SettingToggle
            label="Auto-save Reports"
            description="Automatically save report drafts"
            checked={true}
            onChange={() => {}}
          />

          <SettingToggle
            label="Confirm Destructive Actions"
            description="Require confirmation for delete operations"
            checked={true}
            onChange={() => {}}
          />

          <SettingToggle
            label="Auto-refresh Dashboard"
            description="Automatically refresh stats every 30 seconds"
            checked={false}
            onChange={() => {}}
          />
        </div>
      </div>
    </div>
  )
}

function HuntingSettings({ config, onChange }: { config: any; onChange: (c: any) => void }) {
  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h4 className="font-medium text-slate-900 mb-4">Concurrency & Performance</h4>
        <div className="space-y-4">
          <SettingInput
            label="Max Threads"
            description="Maximum concurrent scanning threads"
            type="number"
            value={config.threads}
            min={1}
            max={200}
            onChange={(v) => onChange({ ...config, threads: parseInt(v) })}
          />

          <SettingInput
            label="Request Timeout (seconds)"
            description="HTTP request timeout"
            type="number"
            value={config.timeout}
            min={5}
            max={300}
            onChange={(v) => onChange({ ...config, timeout: parseInt(v) })}
          />

          <SettingInput
            label="Rate Limit (req/s)"
            description="Maximum requests per second per target"
            type="number"
            value={config.rate_limit_rps}
            min={1}
            max={100}
            onChange={(v) => onChange({ ...config, rate_limit_rps: parseInt(v) })}
          />
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">Scanner Configuration</h4>
        <div className="space-y-3">
          <SettingToggle
            label="Nuclei Scanner"
            description="Template-based vulnerability scanner"
            checked={config.nuclei_enabled}
            onChange={(v) => onChange({ ...config, nuclei_enabled: v })}
          />
          <SettingToggle
            label="DalFox (XSS)"
            description="XSS scanner with blind XSS support"
            checked={config.dalfox_enabled}
            onChange={(v) => onChange({ ...config, dalfox_enabled: v })}
          />
          <SettingToggle
            label="SQLMap"
            description="SQL injection detection and exploitation"
            checked={config.sqlmap_enabled}
            onChange={(v) => onChange({ ...config, sqlmap_enabled: v })}
          />
          <SettingToggle
            label="Custom Payloads"
            description="Test with custom payload lists"
            checked={true}
            onChange={() => {}}
          />
          <SettingToggle
            label="Strict Scope Enforcement"
            description="Block out-of-scope targets completely"
            checked={config.strict_scope}
            onChange={(v) => onChange({ ...config, strict_scope: v })}
          />
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">AI-Powered Hunting</h4>
        <div className="space-y-3">
          <SettingToggle
            label="Enable AI Hunting"
            description="Use LLMs for vulnerability discovery and analysis"
            checked={config.ai_hunting_enabled}
            onChange={(v) => onChange({ ...config, ai_hunting_enabled: v })}
          />
          <SettingToggle
            label="AI Vulnerability Chaining"
            description="Find exploit chains for higher impact"
            checked={false}
            onChange={() => {}}
          />
          <SettingToggle
            label="AI False Positive Reduction"
            description="Use AI to filter false positives"
            checked={true}
            onChange={() => {}}
          />
        </div>
      </div>
    </div>
  )
}

function ValidationSettings({ config, onChange }: { config: any; onChange: (c: any) => void }) {
  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h4 className="font-medium text-slate-900 mb-4">Browser Reproduction</h4>
        <div className="space-y-4">
          <SettingToggle
            label="Headless Mode"
            description="Run browser in headless mode (disable for evidence)"
            checked={config.browser_headless}
            onChange={(v) => onChange({ ...config, browser_headless: v })}
          />
          <SettingInput
            label="Browser Timeout (ms)"
            description="Maximum time to wait for page load"
            type="number"
            value={60000}
            min={10000}
            max={300000}
            onChange={() => {}}
          />
          <SettingToggle
            label="Record Video"
            description="Record full reproduction video"
            checked={true}
            onChange={() => {}}
          />
          <SettingToggle
            label="Capture HAR"
            description="Capture HTTP Archive (HAR) files"
            checked={true}
            onChange={() => {}}
          />
          <SettingToggle
            label="Annotate Screenshots"
            description="Add vulnerability highlights to screenshots"
            checked={true}
            onChange={() => {}}
          />
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">Proxy & Traffic Capture</h4>
        <div className="space-y-3">
          <SettingToggle
            label="Burp Suite Integration"
            description="Route traffic through Burp Suite Professional"
            checked={config.burp_enabled}
            onChange={(v) => onChange({ ...config, burp_enabled: v })}
          />
          <SettingToggle
            label="mitmproxy Fallback"
            description="Use mitmproxy when Burp Pro unavailable"
            checked={config.mitmproxy_fallback}
            onChange={(v) => onChange({ ...config, mitmproxy_fallback: v })}
          />
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">AI Validation</h4>
        <div className="space-y-4">
          <SettingToggle
            label="Enable AI Validation"
            description="Use LLMs to verify findings and reduce false positives"
            checked={config.ai_validation_enabled}
            onChange={(v) => onChange({ ...config, ai_validation_enabled: v })}
          />
          <SettingInput
            label="Confidence Threshold"
            description="Minimum confidence to auto-validate (0.0-1.0)"
            type="number"
            step="0.05"
            value={config.confidence_threshold}
            min={0}
            max={1}
            onChange={(v) => onChange({ ...config, confidence_threshold: parseFloat(v) })}
          />
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">Evidence Collection</h4>
        <div className="space-y-3">
          <SettingToggle
            label="Screenshot on Success"
            description="Capture screenshot when validation succeeds"
            checked={true}
            onChange={() => {}}
          />
          <SettingToggle
            label="Screenshot on Failure"
            description="Capture screenshot when validation fails"
            checked={true}
            onChange={() => {}}
          />
          <SettingToggle
            label="Terminal Recording"
            description="Record terminal sessions for CLI exploits"
            checked={true}
            onChange={() => {}}
          />
        </div>
      </div>
    </div>
  )
}

function AISettings({ config, onChange }: { config: any; onChange: (c: any) => void }) {
  const models = [
    { id: 'llama3.1:70b', name: 'Llama 3.1 70B', desc: 'Best for complex reasoning and analysis' },
    { id: 'llama3.1:8b', name: 'Llama 3.1 8B', desc: 'Faster, lower resource usage' },
    { id: 'deepseek-coder:33b', name: 'DeepSeek Coder 33B', desc: 'Specialized for code analysis and exploits' },
    { id: 'codellama:34b', name: 'CodeLlama 34B', desc: 'Code generation and vulnerability analysis' },
    { id: 'nemotron3-ultra', name: 'Nemotron 3 Ultra', desc: 'Advanced reasoning and chain analysis' },
    { id: 'phi3:14b', name: 'Phi-3 14B', desc: 'Fast triage and classification' },
    { id: 'mistral-nemo', name: 'Mistral Nemo', desc: 'Balanced performance and speed' },
    { id: 'phi3:3.8b', name: 'Phi-3 3.8B', desc: 'Lightweight, minimal resources' },
  ]

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h4 className="font-medium text-slate-900 mb-4">Model Assignment</h4>
        <div className="space-y-4">
          {[
            { key: 'primary_model', label: 'Primary Analysis', desc: 'Main vulnerability analysis and report writing' },
            { key: 'code_model', label: 'Code Analysis', desc: 'Exploit development and POC generation' },
            { key: 'reasoning_model', label: 'Chain Reasoning', desc: 'Vulnerability chaining and impact assessment' },
            { key: 'fast_model', label: 'Fast Triage', desc: 'Quick classification and deduplication' },
          ].map(({ key, label, desc }) => (
            <div key={key} className="p-4 bg-slate-50 rounded-lg">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium text-slate-900">{label}</p>
                  <p className="text-sm text-slate-500">{desc}</p>
                </div>
                <select
                  value={config[key]}
                  onChange={(e) => onChange({ ...config, [key]: e.target.value })}
                  className="select w-56"
                >
                  {models.map(m => (
                    <option key={m.id} value={m.id}>{m.name}</option>
                  ))}
                </select>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">Model Parameters</h4>
        <div className="space-y-4">
          <SettingInput
            label="Temperature"
            description="Randomness in model output (0.0-1.0)"
            type="number"
            step="0.05"
            value={0.1}
            min={0}
            max={1}
            onChange={() => {}}
          />
          <SettingInput
            label="Max Tokens"
            description="Maximum tokens in model response"
            type="number"
            value={8192}
            min={1024}
            max={32768}
            onChange={() => {}}
          />
          <SettingInput
            label="Context Window"
            description="Maximum context size for model"
            type="number"
            value={128000}
            min={4096}
            max={200000}
            onChange={() => {}}
          />
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">Available Models</h4>
        <p className="text-sm text-slate-500 mb-4">Models managed via Ollama. Run <code className="bg-slate-100 px-1.5 py-0.5 rounded">ollama list</code> to see installed models.</p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {models.map(model => (
            <div key={model.id} className="p-3 bg-slate-50 rounded-lg border border-slate-200">
              <p className="font-medium text-slate-900">{model.name}</p>
              <p className="text-sm text-slate-500">{model.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function NotificationSettings({ config, onChange }: { config: any; onChange: (c: any) => void }) {
  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h4 className="font-medium text-slate-900 mb-4">Webhook & Email</h4>
        <div className="space-y-4">
          <SettingInput
            label="Webhook URL"
            description="Discord, Slack, or custom webhook for notifications"
            type="url"
            value={config.webhook_url}
            placeholder="https://hooks.slack.com/services/..."
            onChange={(v) => onChange({ ...config, webhook_url: v })}
          />
          <SettingInput
            label="Email"
            description="Email address for critical alerts"
            type="email"
            value={config.email}
            placeholder="security@company.com"
            onChange={(v) => onChange({ ...config, email: v })}
          />
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">Notification Triggers</h4>
        <div className="space-y-3">
          <SettingToggle
            label="Critical Findings (P1)"
            description="Notify immediately on P1 findings"
            checked={config.on_critical}
            onChange={(v) => onChange({ ...config, on_critical: v })}
          />
          <SettingToggle
            label="High Findings (P2)"
            description="Notify on P2 findings"
            checked={config.on_high}
            onChange={(v) => onChange({ ...config, on_high: v })}
          />
          <SettingToggle
            label="Validated Findings"
            description="Notify when findings are validated"
            checked={config.on_validated}
            onChange={(v) => onChange({ ...config, on_validated: v })}
          />
          <SettingToggle
            label="Scan Completion"
            description="Notify when full hunt completes"
            checked={false}
            onChange={() => {}}
          />
          <SettingToggle
            label="Error Notifications"
            description="Notify on scan errors or failures"
            checked={true}
            onChange={() => {}}
          />
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">Test Notifications</h4>
        <div className="flex gap-3">
          <button className="btn-secondary" onClick={() => alert('Test notification sent!')}>
            Send Test Webhook
          </button>
          <button className="btn-secondary" onClick={() => alert('Test email sent!')}>
            Send Test Email
          </button>
        </div>
      </div>
    </div>
  )
}

function AdvancedSettings() {
  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h4 className="font-medium text-slate-900 mb-4">Database</h4>
        <div className="space-y-4">
          <SettingRow label="Database URL" description="SQLite database connection string">
            <code className="bg-slate-100 px-3 py-2 rounded text-sm font-mono">sqlite:///bug_hunter.db</code>
          </SettingRow>
          <div className="flex gap-3">
            <button className="btn-secondary">Backup Database</button>
            <button className="btn-secondary">Vacuum Database</button>
          </div>
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">External Tools</h4>
        <div className="space-y-3">
          <SettingRow label="Burp Suite Path" description="Path to Burp Suite executable">
            <input className="input w-96" defaultValue="/opt/BurpSuitePro/burpsuitepro" />
          </SettingRow>
          <SettingRow label="Ollama Host" description="Ollama API endpoint">
            <input className="input w-96" defaultValue="http://localhost:11434" />
          </SettingRow>
          <SettingRow label="mitmproxy Port" description="Port for mitmproxy fallback">
            <input className="input w-32" type="number" defaultValue="8081" />
          </SettingRow>
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">Logging & Debugging</h4>
        <div className="space-y-3">
          <SettingRow label="Log Level" description="Minimum log level to record">
            <select className="select w-48">
              <option value="debug">Debug</option>
              <option value="info" selected>Info</option>
              <option value="warn">Warning</option>
              <option value="error">Error</option>
            </select>
          </SettingRow>
          <SettingToggle
            label="Debug Mode"
            description="Enable verbose logging and debug endpoints"
            checked={false}
            onChange={() => {}}
          />
          <SettingToggle
            label="Profile Performance"
            description="Track operation timing for optimization"
            checked={false}
            onChange={() => {}}
          />
        </div>
      </div>

      <div className="pt-6 border-t border-slate-200">
        <h4 className="font-medium text-slate-900 mb-4">Data Management</h4>
        <div className="space-y-3">
          <div className="flex items-center justify-between p-4 bg-slate-50 rounded-lg">
            <div>
              <p className="font-medium text-slate-900">Export All Data</p>
              <p className="text-sm text-slate-500">Download complete database as JSON</p>
            </div>
            <button className="btn-secondary">Export Data</button>
          </div>
          <div className="flex items-center justify-between p-4 bg-slate-50 rounded-lg">
            <div>
              <p className="font-medium text-slate-900">Import Data</p>
              <p className="text-sm text-slate-500">Restore from JSON backup</p>
            </div>
            <button className="btn-secondary">Import Data</button>
          </div>
        </div>
      </div>
    </div>
  )
}

function SettingRow({ label, description, children }: { label: string; description: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="flex-1 min-w-0">
        <p className="font-medium text-slate-900">{label}</p>
        <p className="text-sm text-slate-500 mt-0.5">{description}</p>
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  )
}

function SettingInput({ label, description, ...props }: { label: string; description: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="flex-1 min-w-0">
        <p className="font-medium text-slate-900">{label}</p>
        <p className="text-sm text-slate-500 mt-0.5">{description}</p>
      </div>
      <input {...props} className="input w-48" />
    </div>
  )
}

function SettingToggle({ label, description, checked, onChange }: { label: string; description: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <p className="font-medium text-slate-900">{label}</p>
        <p className="text-sm text-slate-500">{description}</p>
      </div>
      <button
        onClick={() => onChange(!checked)}
        className={clsx('relative w-11 h-6 rounded-full transition-colors', checked ? 'bg-primary-600' : 'bg-slate-300')}
        role="switch"
        aria-checked={checked}
      >
        <span className={clsx('absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform', checked ? 'translate-x-5' : 'translate-x-0.5')} />
      </button>
    </div>
  )
}

import React from 'react'
import { clsx } from 'clsx'