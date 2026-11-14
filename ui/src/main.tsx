import React, { useCallback, useEffect, useRef, useState } from 'react'
import ReactDOM from 'react-dom/client'
import { createClient } from '@supabase/supabase-js'
import type { Session, SupabaseClient } from '@supabase/supabase-js'
import { ArrowDown, ArrowRight, Check, CheckCheck, ChevronRight, Copy, Cpu, LogOut, Plus, RefreshCw, Server, Terminal, X } from 'lucide-react'
import './style.css'
import { api } from './api'
import { OperatorSecrets, enrollSecretsService, enrollmentEnvelope } from './operator-secrets'
import { bootstrapCommand } from './bootstrap'
import { Administration } from './administration'
import { OrchestratorWorkspace } from './orchestrators'
import { clearInvitation, pendingInvitation } from './orchestrator-members'
import { MachineStatus, MachineReadinessBadge } from './machine-status'

type AuthConfig = { supabase_url: string; supabase_publishable_key: string }
type OperatorConfig = { public_api_url: string; secrets_url: string }
type Machine = { node_id: string; terminal?: boolean; lifecycle?: string; report_state?: string; hostname: string; created_at: string; last_config_fetch_at: string | null }
type Enrollment = { token: string; expires_at: string }

function Brand({ dark = false }: { dark?: boolean }) {
  return <a className={`brand ${dark ? 'brand-light' : ''}`} href="/" aria-label="Livepeer Control Center home"><span className="brand-mark" aria-hidden="true"><svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M3 3h5v5H3zM3 10h5v5H3zM3 17h5v5H3zM10 10h5v5h-5zM10 17h5v5h-5zM17 17h5v5h-5z" /></svg></span><span className="brand-name">Livepeer<span>Control Center</span></span></a>
}

function GoogleIcon() {
  return <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path fill="#4285F4" d="M21.6 12.23c0-.71-.06-1.39-.18-2.05H12v3.88h5.38a4.6 4.6 0 0 1-2 3.02v2.51h3.24c1.9-1.75 2.98-4.33 2.98-7.36Z"/><path fill="#34A853" d="M12 22c2.7 0 4.96-.9 6.62-2.41l-3.24-2.51c-.9.6-2.05.96-3.38.96-2.6 0-4.8-1.76-5.58-4.12H3.08v2.59A10 10 0 0 0 12 22Z"/><path fill="#FBBC05" d="M6.42 13.92a6 6 0 0 1 0-3.84V7.49H3.08a10 10 0 0 0 0 9.02l3.34-2.59Z"/><path fill="#EA4335" d="M12 5.96c1.47 0 2.79.51 3.83 1.51l2.88-2.88A9.6 9.6 0 0 0 12 2a10 10 0 0 0-8.92 5.49l3.34 2.59C7.2 7.72 9.4 5.96 12 5.96Z"/></svg>
}

function Notice({ children, kind = 'error' }: { children: React.ReactNode; kind?: 'error' | 'success' }) {
  return <div className={`notice ${kind}`} role={kind === 'error' ? 'alert' : 'status'}>{children}</div>
}

function Login({ client }: { client: SupabaseClient }) {
  const [signup, setSignup] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState('')
  const [message, setMessage] = useState('')
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setProblem(''); setMessage('')
    try {
      const result = signup
        ? await client.auth.signUp({ email, password, options: { emailRedirectTo: `${window.location.origin}/auth/callback` } })
        : await client.auth.signInWithPassword({ email, password })
      if (result.error) throw result.error
      if (signup && !result.data.session) setMessage('Check your email to confirm your account, then come back to sign in.')
    } catch (error) { setProblem(error instanceof Error ? error.message : 'Could not sign in. Please try again.') }
    finally { setBusy(false) }
  }
  async function google() {
    setBusy(true); setProblem('')
    try {
      const { error } = await client.auth.signInWithOAuth({ provider: 'google', options: { redirectTo: `${window.location.origin}/auth/callback` } })
      if (error) throw error
    } catch (error) { setProblem(error instanceof Error ? error.message : 'Could not start Google sign-in.'); setBusy(false) }
  }
  return <div className="auth-layout">
    <aside className="auth-story">
      <Brand dark />
      <div className="story-content"><span className="eyebrow"><span className="live-dot" /> BUILT FOR THE OPEN NETWORK</span>
        <h1>Your compute.<br /><span>Connected.</span></h1>
        <p>Bring your machines to Livepeer.<br />One command gets you started.</p>
        <div className="network-art" aria-hidden="true">
          <div className="network-line horizontal" /><div className="network-line vertical" />
          <div className="network-node node-one"><Server size={23} /></div>
          <div className="network-node node-two"><Cpu size={23} /></div>
          <div className="network-core"><span className="core-pixel" /><span className="core-pixel" /><span className="core-pixel" /><span className="core-pixel" /></div>
          <div className="network-node node-three"><Server size={23} /></div>
          <span className="network-caption">YOUR HARDWARE. A WORLD OF POSSIBILITIES.</span>
        </div>
      </div>
      <div className="story-footer"><span>INDEPENDENT MACHINES. SHARED POTENTIAL.</span><span>01 — ∞</span></div>
    </aside>
    <main className="auth-main">
      <span className="auth-top-label">THE LIVEPEER MACHINE CONSOLE</span>
      <div className="auth-form-wrap"><div className="small-icon"><Terminal size={21} /></div>
        <h2>{signup ? 'Make yourself at home.' : 'Welcome back.'}</h2>
        <p className="muted auth-description">{signup ? 'Create an account to connect your first machine.' : 'Sign in to your machines and keep things moving.'}</p>
        <button className="button google-button" onClick={google} disabled={busy}><GoogleIcon />Continue with Google</button>
        <div className="divider"><span />or continue with email<span /></div>
        <form onSubmit={submit}>
          <label htmlFor="email">Email address</label><input id="email" name="email" type="email" autoComplete="email" placeholder="you@example.com" required value={email} onChange={e => setEmail(e.target.value)} />
          <label htmlFor="password">Password{signup && <span className="field-hint">At least 8 characters</span>}</label><input id="password" name="password" type="password" autoComplete={signup ? 'new-password' : 'current-password'} minLength={signup ? 8 : undefined} placeholder="Enter your password" required value={password} onChange={e => setPassword(e.target.value)} />
          {problem && <Notice>{problem}</Notice>}{message && <Notice kind="success">{message}</Notice>}
          <button className="button primary" type="submit" disabled={busy}>{busy ? 'Please wait…' : signup ? 'Create account' : 'Sign in'}<ArrowRight size={17} /></button>
        </form>
        <p className="switch-auth">{signup ? 'Already have an account?' : 'New here?'} <button onClick={() => { setSignup(!signup); setProblem(''); setMessage('') }}>{signup ? 'Sign in' : 'Create an account'}<ChevronRight size={14} /></button></p>
        <div className="auth-footnote"><Check size={14} />Your machines stay yours. Always.</div>
      </div>
      <span className="auth-bottom-label">A LITTLE SETUP. A LOT OF POSSIBILITY.</span>
    </main>
  </div>
}

function MachineConsole({ session, address, authorityFailure }: { session: Session; address: string; authorityFailure: (error: unknown) => void }) {
  const [config, setConfig] = useState<OperatorConfig | null>(null)
  const [enrollment, setEnrollment] = useState<(Enrollment & OperatorConfig) | null>(null)
  const [machines, setMachines] = useState<Machine[] | null>(null)
  const [tokenProblem, setTokenProblem] = useState('')
  const [machineProblem, setMachineProblem] = useState('')
  const [selectedMachine, setSelectedMachine] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)
  const [now, setNow] = useState(Date.now())
  const generation = useRef<AbortController | null>(null)
  useEffect(() => () => generation.current?.abort(), [])
  const generate = useCallback(async () => {
    generation.current?.abort()
    const controller = new AbortController(); generation.current = controller
    const signal = controller.signal
    setBusy(true); setTokenProblem(''); setCopied(false)
    try {
      const settings = await api<OperatorConfig>(session, '/api/operator/config', { signal })
      if (signal.aborted) return
      setConfig(settings)
      const control = await api<Enrollment>(session, '/api/bootstrap-token', { method: 'POST', signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ orchestrator_address: address }) })
      const setup = await enrollSecretsService<Enrollment>(session, settings.secrets_url, address, signal)
      control.token = enrollmentEnvelope(control.token, setup.token)
      control.expires_at = new Date(Math.min(Date.parse(control.expires_at), Date.parse(setup.expires_at))).toISOString()
      if (!signal.aborted) setEnrollment({ ...control, ...settings })
    }
    catch (error) { if (!signal.aborted) { setTokenProblem(error instanceof Error ? error.message : 'Could not generate a command.'); authorityFailure(error) } }
    finally { if (!signal.aborted) setBusy(false) }
  }, [session.access_token, address, authorityFailure])
  useEffect(() => { void generate() }, [generate])
  useEffect(() => {
    const controller = new AbortController()
    let pending = false
    const refresh = async () => {
      if (pending || document.hidden) return
      pending = true
      try {
        const data = await api<{ machines: Machine[] }>(session, `/api/machines?orchestrator_address=${encodeURIComponent(address)}`, { signal: controller.signal })
        if (!controller.signal.aborted) { setMachines(data.machines); setMachineProblem('') }
      } catch (error) { if (!controller.signal.aborted) { setMachineProblem(error instanceof Error ? error.message : 'Could not load machines.'); authorityFailure(error) } }
      finally { pending = false }
    }
    void refresh()
    const interval = window.setInterval(refresh, 5000)
    document.addEventListener('visibilitychange', refresh)
    return () => { controller.abort(); window.clearInterval(interval); document.removeEventListener('visibilitychange', refresh) }
  }, [session.access_token, address, authorityFailure])
  useEffect(() => { const interval = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(interval) }, [])
  const seconds = enrollment ? Math.max(0, Math.floor((Date.parse(enrollment.expires_at) - now) / 1000)) : 0
  const command = enrollment ? bootstrapCommand(window.location.origin, enrollment.public_api_url, enrollment.token, enrollment.secrets_url) : ''
  async function copy() {
    try { await navigator.clipboard.writeText(command); setCopied(true); window.setTimeout(() => setCopied(false), 2500) }
    catch { setTokenProblem('Clipboard access is unavailable. Select and copy the command below.') }
  }
  return <>
      <div className="breadcrumb">ORCHESTRATOR<ChevronRight size={12} /><span>OVERVIEW</span></div>
      <div className="page-heading"><div><span className="eyebrow green">YOUR COMPUTE, CONNECTED</span><h1>Let’s put your machines to work.</h1><p className="muted">Connect a machine. We’ll take care of the configuration.</p></div><a href="#machines" className="text-link">View machines<ArrowDown size={15} /></a></div>
      <div className="onboarding-grid">
        <section className="connect-card" aria-labelledby="connect-title">
          <div className="connect-heading"><span className="terminal-badge"><Terminal size={19} /></span><span>CONNECT A MACHINE</span><span className="step-pill">01 / 02</span></div>
          <h2 id="connect-title">One command. You’re connected.</h2><p>Run this on your machine to enroll it with this orchestrator.</p>
          <div className="command-window"><div className="command-bar"><div className="window-dots"><i /><i /><i /></div><span>root@your-machine ~</span><span>POSIX SH</span></div><div className="command-body"><span className="prompt">$</span><code aria-label="Bootstrap command">{command || (busy ? 'Generating your command…' : 'Generate a command to get started.')}</code></div></div>
          {tokenProblem && <Notice>{tokenProblem}</Notice>}
          <div className="command-actions"><button className="button lime" onClick={copy} disabled={!enrollment || seconds === 0 || busy}>{copied ? <CheckCheck size={16} /> : <Copy size={16} />}{copied ? 'Command copied' : 'Copy command'}</button><button className="regenerate" onClick={generate} disabled={busy}><RefreshCw size={14} className={busy ? 'spin' : ''} />{seconds === 0 && enrollment ? 'Generate new token' : 'Refresh token'}</button><span className="expiry"><span className={`status-dot ${seconds > 0 ? 'active' : ''}`} />{enrollment ? seconds > 0 ? `Expires in ${Math.ceil(seconds / 60)} min` : 'Token expired' : 'One-hour enrollment window'}</span></div>
          <div className="connect-footer"><Check size={14} /><span>Use the same command on multiple machines before it expires.</span></div>
        </section>
        <aside className="before-card"><span className="eyebrow">BEFORE YOU RUN</span><h3>A quick preflight.</h3><ol className="preflight-list"><li><span>1</span><div><strong>Start with a Linux machine</strong><p>Debian or Ubuntu · amd64<br />2 CPUs · 4 GB RAM · 10 GB free</p></div></li><li><span>2</span><div><strong>Prepare the host tools</strong><p>Install curl, jq, nftables and the other <a href="https://github.com/livepeer/control-center/blob/main/runtime/README.md#prerequisites">prerequisite packages</a>. The API and image registries must be reachable from the host and its pods.</p></div></li><li><span>3</span><div><strong>Run as root</strong><p>Run the command on the target host. See the <a href="https://github.com/livepeer/control-center/blob/main/runtime/README.md">sudo instructions</a> if needed.</p></div></li></ol><div className="preflight-note"><Terminal size={15} /><span>Your machine handles the setup.<br />Keep the terminal open until it finishes.</span></div></aside>
      </div>
      <section id="machines" className="machines-section" aria-labelledby="machines-title"><div className="section-heading"><div><h2 id="machines-title">Your machines<span className="count">{machines?.length ?? '—'}</span></h2><p className="muted">Every connected machine, in one place.</p></div><span className="auto-refresh"><span className="status-dot active" />Updates automatically</span></div>
        {machineProblem && <Notice>{machineProblem}</Notice>}
        <div className="machine-panel">{machines === null ? <div className="empty-state"><RefreshCw size={22} className="spin" /><h3>Loading your machines…</h3></div> : machines.length === 0 ? <div className="empty-state"><div className="empty-icon"><Server size={25} /><span><Plus size={12} /></span></div><h3>Your first machine starts here.</h3><p>Run the command above. Your machine will appear<br />here as soon as enrollment succeeds.</p><a href="#connect-title" className="text-link">Ready when you are<ArrowRight size={15} /></a></div> : <div className="table-scroll"><table><thead><tr><th>MACHINE</th><th>WORK READINESS</th><th>ENROLLED / RETIRED</th><th>LAST CONFIG REQUEST</th><th>RUNTIME</th></tr></thead><tbody>{machines.map(machine => <tr key={machine.node_id}><td><div className="machine-name"><span className="machine-glyph"><Server size={17} /></span><div><strong>{machine.hostname}</strong><code>{machine.node_id}</code></div></div></td><td><MachineReadinessBadge machine={machine} /></td><td>{new Date(machine.created_at).toLocaleString()}</td><td>{machine.last_config_fetch_at ? new Date(machine.last_config_fetch_at).toLocaleString() : 'Awaiting first request'}</td><td><button className="button" aria-label={`View status for ${machine.hostname}`} onClick={() => setSelectedMachine(machine.node_id)}>View status</button></td></tr>)}</tbody></table></div>}</div>
        <p className="table-note">Open View status to check work readiness, deployment, apps, tunnel provisioning and discovery. Runtime reporting alone does not mean a node can receive work.</p>
      </section>
      {machines?.filter(m => m.node_id === selectedMachine).map(m => <MachineStatus key={`${session.user.id}:${m.node_id}`} session={session} machine={m} authorityFailure={authorityFailure} />)}
      {config && <OperatorSecrets session={session} origin={config.secrets_url} address={address} authorityFailure={authorityFailure} />}
  </>
}

function Dashboard({ client, session, invitation, dismissInvitation }: { client: SupabaseClient; session: Session; invitation: string | null; dismissInvitation: () => void }) {
  const [logoutProblem, setLogoutProblem] = useState('')
  async function logout() {
    const { error } = await client.auth.signOut()
    if (error) setLogoutProblem(error.message)
  }
  return <div className="console">
    <OrchestratorWorkspace session={session} invitation={invitation} clearInvitation={dismissInvitation} header={selector => <header className="topbar"><Brand /><span className="header-divider" />{selector}<div className="account"><span className="avatar">{(session.user.email || 'U')[0].toUpperCase()}</span><span className="account-email">{session.user.email}</span><button className="icon-button" aria-label="Sign out" title="Sign out" onClick={logout}><LogOut size={17} /></button></div></header>}>
      {(address, authorityFailure) => <main className="dashboard">
        {logoutProblem && <Notice>{logoutProblem}</Notice>}
        {address && <MachineConsole key={`${session.user.id}:${address}`} session={session} address={address} authorityFailure={authorityFailure} />}
        <Administration key={session.user.id} session={session} />
        <footer className="dashboard-footer"><span>LIVEPEER / CONTROL CENTER</span><span>YOUR MACHINES. OPEN POSSIBILITIES.</span></footer>
      </main>}
    </OrchestratorWorkspace>
  </div>
}

function App() {
  const [invitation, setInvitation] = useState(pendingInvitation)
  const dismissInvitation = () => { clearInvitation(); setInvitation(null) }
  useEffect(() => {
    const receive = () => {
      if (window.location.pathname === '/invite' && window.location.hash) setInvitation(pendingInvitation())
    }
    window.addEventListener('hashchange', receive)
    return () => window.removeEventListener('hashchange', receive)
  }, [])
  const [client, setClient] = useState<SupabaseClient | null>(null)
  const [session, setSession] = useState<Session | null>(null)
  const [ready, setReady] = useState(false)
  const [problem, setProblem] = useState('')
  useEffect(() => {
    let active = true
    let dispose: (() => void) | undefined
    async function load() {
      try {
        const response = await fetch('/api/config')
        if (!response.ok) throw new Error('The console could not reach the API. Check that the backend is running.')
        const settings = await response.json() as AuthConfig
        if (!active) return
        const callbackURL = new URL(window.location.href)
        const callbackError = [callbackURL.searchParams, new URLSearchParams(callbackURL.hash.slice(1))]
          .map(params => params.get('error_description') || params.get('error')).find(Boolean)
        const auth = createClient(settings.supabase_url, settings.supabase_publishable_key, { auth: { flowType: 'pkce', detectSessionInUrl: true } })
        setClient(auth)
        const { data: { subscription } } = auth.auth.onAuthStateChange((_event, next) => { if (active) setSession(next) })
        dispose = () => subscription.unsubscribe()
        const initialized = await auth.auth.initialize()
        const { data, error } = await auth.auth.getSession()
        if (!active) return
        if (error) throw error
        setSession(data.session); setReady(true)
        if (initialized.error || callbackError) setProblem(initialized.error?.message || callbackError!)
        if (callbackURL.pathname === '/auth/callback') window.history.replaceState({}, '', '/')
      } catch (error) { if (active) { setProblem(error instanceof Error ? error.message : 'Could not load the console.'); setReady(true) } }
    }
    void load()
    return () => { active = false; dispose?.() }
  }, [])
  if (!ready) return <div className="loading-screen"><Brand /><RefreshCw size={22} className="spin" /><p>Opening your workspace…</p></div>
  if (!client) return <div className="loading-screen"><Brand /><Notice>{problem || 'Configuration unavailable.'}</Notice><button className="button primary" onClick={() => window.location.reload()}>Try again<RefreshCw size={16} /></button></div>
  return <>{problem && <div className="callback-error"><span>{problem}</span><button className="icon-button" aria-label="Dismiss message" onClick={() => setProblem('')}><X size={16} /></button></div>}{session ? <Dashboard key={session.user.id} client={client} session={session} invitation={invitation} dismissInvitation={dismissInvitation} /> : <Login client={client} />}</>
}

ReactDOM.createRoot(document.getElementById('root')!).render(<App />)
