import { useEffect, useRef, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { api, APIError } from './api'
import { Catalog } from './catalog'
import { MachineApps } from './machine-apps'

type Grant = { grant_id: string; email: string; user_id: string | null; current_email: string | null; revision: number; state: 'pending' | 'bound' | 'account_missing' }
type FleetMachine = { node_id: string; epoch: string; hostname: string; owner_id: string; k3s_version: string; created_at: string; last_config_fetch_at: string | null }
type Capability = 'loading' | 'admin' | 'ordinary' | 'unavailable'

// Keyed by account in Dashboard. Request versions reject obsolete successes
// after a newer failure in the same session.
export function Administration({ session }: { session: Session }) {
  const [capability, setCapability] = useState<Capability>('loading')
  const [grants, setGrants] = useState<Grant[]>([])
  const [machines, setMachines] = useState<FleetMachine[]>([])
  const [selectedMachine, setSelectedMachine] = useState<string | null>(null)
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState('')
  const [accessProblem, setAccessProblem] = useState('')
  const [message, setMessage] = useState('')
  const version = useRef(0)
  const requests = useRef(new Set<AbortController>())
  const mutating = useRef(false)
  const refreshing = useRef(false)
  const mounted = useRef(true)
  const refresh = useRef<() => void>(() => {})

  function invalidate(next: Capability) {
    version.current++
    requests.current.forEach(controller => controller.abort()); requests.current.clear()
    refreshing.current = false
    setSelectedMachine(null); setCapability(next); setGrants([]); setMachines([]); setMessage(''); setEmail(''); setBusy(false); mutating.current = false
  }

  useEffect(() => {
    let alive = true
    mounted.current = true
    refreshing.current = false
    mutating.current = false; setBusy(false)
    refresh.current = async () => {
      if (!alive || document.hidden || mutating.current || refreshing.current) return
      refreshing.current = true
      const ticket = ++version.current
      const controller = new AbortController()
      requests.current.add(controller)
      const current = () => alive && ticket === version.current && !controller.signal.aborted
      try {
        const me = await api<{ user_id: string; is_admin: boolean }>(session, '/api/me', { signal: controller.signal })
        if (!current()) return
        if (me.user_id !== session.user.id) throw new APIError(401, 'Sign in again to verify your account.')
        if (!me.is_admin) { invalidate('ordinary'); return }
        const [access, fleet] = await Promise.all([
          api<{ administrators: Grant[] }>(session, '/api/admin/administrators', { signal: controller.signal }),
          api<{ machines: FleetMachine[] }>(session, '/api/admin/machines', { signal: controller.signal }),
        ])
        if (!current()) return
        setCapability('admin'); setGrants(access.administrators); setMachines(fleet.machines); setAccessProblem('')
      } catch (error) {
        if (!current()) return
        invalidate(error instanceof APIError && [401, 403].includes(error.status) ? 'ordinary' : 'unavailable')
        setAccessProblem(error instanceof APIError ? error.message : 'Administrator access is unavailable. Retrying automatically.')
      } finally {
        requests.current.delete(controller)
        if (ticket === version.current) refreshing.current = false
      }
    }
    refresh.current()
    const timer = window.setInterval(() => refresh.current(), 5000)
    const visible = () => refresh.current()
    document.addEventListener('visibilitychange', visible)
    return () => {
      alive = false; mounted.current = false; version.current++
      requests.current.forEach(controller => controller.abort()); requests.current.clear()
      window.clearInterval(timer); document.removeEventListener('visibilitychange', visible)
    }
  }, [session.access_token, session.user.id])

  async function change(path: string, method: string, body?: unknown) {
    if (mutating.current || capability !== 'admin') return
    version.current++
    requests.current.forEach(controller => controller.abort()); requests.current.clear()
    refreshing.current = false
    mutating.current = true; setBusy(true); setProblem(''); setMessage('')
    const ticket = version.current
    const controller = new AbortController()
    requests.current.add(controller)
    try {
      await api(session, path, { method, signal: controller.signal, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
      if (ticket !== version.current || controller.signal.aborted) return
      setEmail(''); setMessage(method === 'POST' ? 'Administrator access granted.' : 'Administrator access revoked.')
    } catch (error) {
      if (ticket !== version.current || controller.signal.aborted) return
      if (error instanceof APIError && [401, 403, 503].includes(error.status)) invalidate(error.status === 503 ? 'unavailable' : 'ordinary')
      setProblem(error instanceof Error ? error.message : 'Could not update administrator access.')
    } finally {
      requests.current.delete(controller)
      if (ticket !== version.current || controller.signal.aborted) return
      mutating.current = false
      if (mounted.current) { setBusy(false); refresh.current() }
    }
  }

  if (capability !== 'admin') return capability === 'unavailable' ? <div className="notice error" role="alert">{accessProblem || problem || 'Administrator access is unavailable. Retrying automatically.'}</div> : null
  return <section className="administration" aria-labelledby="administration-title">
    <div className="section-heading"><div><h2 id="administration-title">Administration</h2><p className="muted">Manage administrator access and view the machine fleet.</p></div></div>
    {problem && <div className="notice error" role="alert">{problem}</div>}
    {message && <div className="notice success" role="status">{message}</div>}
    <div className="admin-access">
      <h3>Administrators</h3>
      <form className="admin-grant" onSubmit={event => { event.preventDefault(); void change('/api/admin/administrators', 'POST', { email }) }}>
        <div><label htmlFor="admin-email">Existing account email</label><input id="admin-email" type="email" required value={email} onChange={event => setEmail(event.target.value)} placeholder="person@example.com" disabled={busy} /></div>
        <button className="button lime" type="submit" disabled={busy}>Grant access</button>
      </form>
      <p className="table-note">Grant access only after the account’s email verification history has been established.</p>
      <ul className="admin-list">{grants.map(grant => <li key={grant.grant_id}><div><strong>{grant.current_email || grant.email}</strong><span className="muted">{grant.user_id === session.user.id ? 'You' : grant.state === 'pending' ? 'Pending verified sign-in' : grant.state === 'account_missing' ? 'Account deleted or unavailable' : 'Administrator'}</span>{grant.user_id && <code>{grant.user_id}</code>}</div><button className="button" disabled={busy || grant.user_id === session.user.id} title={grant.user_id === session.user.id ? 'Another administrator must revoke your access.' : undefined} onClick={() => void change(`/api/admin/administrators/${grant.grant_id}`, 'DELETE')}>Revoke</button></li>)}</ul>
    </div>
    <Catalog session={session} authorityFailure={error => { invalidate(error.status === 503 ? 'unavailable' : 'ordinary'); setAccessProblem(error.message) }} />
    <h3>Machine fleet <span className="count">{machines.length}</span></h3>
    <div className="machine-panel table-scroll"><table><thead><tr><th>MACHINE</th><th>OWNER</th><th>K3S VERSION</th><th>LAST CONFIG REQUEST</th><th>APPS</th></tr></thead><tbody>{machines.map(machine => <tr key={machine.node_id}><td><strong>{machine.hostname}</strong><code>{machine.node_id}</code></td><td><code>{machine.owner_id}</code></td><td>{machine.k3s_version}</td><td>{machine.last_config_fetch_at ? new Date(machine.last_config_fetch_at).toLocaleString() : 'Awaiting first request'}</td><td><button className="button" aria-label={`Manage apps for ${machine.hostname}`} disabled={!machine.epoch} onClick={() => setSelectedMachine(machine.node_id)}>Manage apps</button></td></tr>)}</tbody></table>{machines.length === 0 && <p className="admin-empty muted">No machines enrolled.</p>}</div>
    {machines.filter(m => m.node_id === selectedMachine).map(machine => <MachineApps key={`${session.user.id}:${machine.node_id}:${machine.epoch}`} session={session} machine={machine} authorityFailure={error => { invalidate(error.status === 503 ? 'unavailable' : 'ordinary'); setAccessProblem(error.message) }} />)}
  </section>
}
