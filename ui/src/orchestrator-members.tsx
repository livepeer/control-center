import { useCallback, useEffect, useRef, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { api } from './api'

const pendingKey = 'lpcc-pending-invitation'

// Capture before Auth inspects the callback URL. Session storage carries the
// invitation across OAuth redirects without putting it in callback URLs.
export function pendingInvitation(): string | null {
  const url = new URL(window.location.href)
  const token = url.pathname === '/invite' ? new URLSearchParams(url.hash.slice(1)).get('token') : null
  if (token) {
    try { sessionStorage.setItem(pendingKey, token) } catch { /* Password sign-in still works in memory. */ }
    window.history.replaceState({}, '', '/invite')
    return token
  }
  try { return sessionStorage.getItem(pendingKey) } catch { return null }
}

export function clearInvitation() {
  try { sessionStorage.removeItem(pendingKey) } catch { /* Optional browser storage. */ }
  if (window.location.pathname === '/invite') window.history.replaceState({}, '', '/')
}

type ScopeProps = { session: Session; address: string; authorityFailure: (error: unknown) => void; changed: () => Promise<void> }
type Member = { user_id: string; email: string }

export function OrchestratorMembers({ session, address, authorityFailure, changed }: ScopeProps) {
  const [open, setOpen] = useState(false)
  const [members, setMembers] = useState<Member[] | null>(null)
  const [problem, setProblem] = useState('')
  const [busy, setBusy] = useState(false)
  const [link, setLink] = useState('')
  const [expires, setExpires] = useState('')
  const [copied, setCopied] = useState(false)
  const active = useRef<AbortController | null>(null)
  const latestRead = useRef(0)
  const path = `/api/orchestrators/${encodeURIComponent(address)}`
  const refresh = useCallback(async (signal: AbortSignal) => {
    const generation = ++latestRead.current
    try {
      const result = await api<{ members: Member[] }>(session, `${path}/members`, { signal })
      if (!signal.aborted && generation === latestRead.current) { setMembers(result.members); setProblem('') }
    } catch (error) {
      if (!signal.aborted && generation === latestRead.current) { setProblem(error instanceof Error ? error.message : 'Could not load members.'); authorityFailure(error) }
    }
  }, [session.access_token, path, authorityFailure])
  useEffect(() => {
    const controller = new AbortController(); active.current = controller
    setBusy(false)
    const load = () => { if (open) void refresh(controller.signal) }
    load(); window.addEventListener('focus', load)
    return () => { controller.abort(); window.removeEventListener('focus', load) }
  }, [open, refresh])
  const invite = async () => {
    const signal = active.current!.signal
    setBusy(true); setProblem(''); setCopied(false)
    try {
      const result = await api<{ token: string; expires_at: string }>(session, `${path}/invitations`, { method: 'POST', signal })
      if (!signal.aborted) { setLink(`${window.location.origin}/invite#token=${encodeURIComponent(result.token)}`); setExpires(result.expires_at) }
    } catch (error) {
      if (!signal.aborted) { setProblem(error instanceof Error ? error.message : 'Could not create invitation.'); authorityFailure(error) }
    } finally { if (!signal.aborted) setBusy(false) }
  }
  const remove = async (member: Member) => {
    const self = member.user_id === session.user.id
    if (!window.confirm(self ? 'Leave this orchestrator? You will lose access to its machines and secrets.' : `Remove ${member.email || member.user_id} from this orchestrator?`)) return
    const signal = active.current!.signal
    setBusy(true); setProblem('')
    try {
      await api(session, `${path}/members/${encodeURIComponent(member.user_id)}`, { method: 'DELETE', signal })
      if (signal.aborted) return
      if (self) await changed()
      else await refresh(signal)
    } catch (error) {
      if (!signal.aborted) { setProblem(error instanceof Error ? error.message : 'Could not remove member.'); authorityFailure(error) }
    } finally { if (!signal.aborted) setBusy(false) }
  }
  const copy = async () => {
    const signal = active.current!.signal
    try { await navigator.clipboard.writeText(link); if (!signal.aborted) setCopied(true) }
    catch { if (!signal.aborted) setProblem('Select and copy the invitation link below.') }
  }
  return <details className="members-panel" onToggle={e => setOpen(e.currentTarget.open)}>
    <summary>Members</summary>
    {open && <div className="members-body">
      <p>Every member can invite people, remove members, and leave. The last member must stay until someone else joins.</p>
      {problem && <p className="notice error" role="alert">{problem}<button className="button" disabled={busy} onClick={() => void refresh(active.current!.signal)}>Reload members</button></p>}
      {members === null ? <p role="status">Loading members…</p> : <ul className="member-list">{members.map(member => <li key={member.user_id}>
        <span>{member.email || member.user_id}{member.user_id === session.user.id && <small> You</small>}</span>
        <button className="button" disabled={busy || (member.user_id === session.user.id && members.length === 1)} onClick={() => void remove(member)}>{member.user_id === session.user.id ? 'Leave orchestrator' : 'Remove member'}</button>
      </li>)}</ul>}
      {members?.length === 1 && members[0].user_id === session.user.id && <p className="muted">You are the last member. Invite someone and wait for them to join before leaving.</p>}
      <button className="button" disabled={busy} onClick={() => void invite()}>Create invitation link</button>
      {link && <div className="invitation-link"><label>Invitation link<input aria-label="Invitation link" readOnly value={link} onFocus={e => e.target.select()} /></label><button className="button" onClick={() => void copy()}>{copied ? 'Link copied' : 'Copy invitation link'}</button><p>One person can accept this link. It expires {new Date(expires).toLocaleString()} (24 hours after creation).</p></div>}
    </div>}
  </details>
}

type Preview = { address: string; display_name: string; expires_at: string }
export function InvitationAcceptance({ session, token, accepted, dismiss }: { session: Session; token: string; accepted: (address: string, signal: AbortSignal) => Promise<void>; dismiss: () => void }) {
  const [preview, setPreview] = useState<Preview | null>(null)
  const [problem, setProblem] = useState('')
  const [busy, setBusy] = useState(false)
  const [retry, setRetry] = useState(0)
  const active = useRef<AbortController | null>(null)
  // Token renewal must not cancel acceptance after the server consumes the link.
  const latestSession = useRef(session)
  latestSession.current = session
  useEffect(() => {
    const controller = new AbortController(); active.current = controller
    setPreview(null); setProblem(''); setBusy(false)
    void api<Preview>(latestSession.current, '/api/orchestrator-invitations/preview', { method: 'POST', signal: controller.signal, body: JSON.stringify({ token }) })
      .then(result => { if (!controller.signal.aborted) setPreview(result) })
      .catch(error => { if (!controller.signal.aborted) setProblem(error instanceof Error ? error.message : 'Could not load invitation.') })
    return () => controller.abort()
  }, [token, retry])
  const accept = async () => {
    const signal = active.current!.signal
    setBusy(true); setProblem('')
    try {
      const result = await api<{ address: string }>(latestSession.current, '/api/orchestrator-invitations/accept', { method: 'POST', signal, body: JSON.stringify({ token }) })
      if (!signal.aborted) await accepted(result.address, signal)
    } catch (error) { if (!signal.aborted) setProblem(error instanceof Error ? error.message : 'Could not accept invitation.') }
    finally { if (!signal.aborted) setBusy(false) }
  }
  return <section className="members-panel invitation-acceptance" aria-label="Orchestrator invitation">
    <h2>Join an orchestrator</h2>
    <p>Signed in as <strong>{session.user.email || session.user.id}</strong>.</p>
    {preview ? <><p>{preview.display_name && <strong>{preview.display_name} · </strong>}<span>{preview.address}</span></p><p>Join with the same permissions as every other member. Invitation expires {new Date(preview.expires_at).toLocaleString()}.</p><button className="button primary" disabled={busy} onClick={() => void accept()}>{busy ? 'Joining…' : 'Accept invitation'}</button></> : !problem && <p role="status">Loading invitation…</p>}
    {problem && <p className="notice error" role="alert">{problem}<button className="button" disabled={busy} onClick={() => setRetry(value => value + 1)}>Retry invitation</button></p>}
    <button className="button" disabled={busy} onClick={dismiss}>Dismiss invitation</button>
  </section>
}
