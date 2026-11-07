import { useEffect, useRef, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { api, APIError } from './api'

type Ref = { revision_id: string; digest: string }
type Lifecycle = { version: number; retired_at: string | null; retired_by: string | null }
type Summary = Ref & { revision: number; app_version: string; lifecycle: Lifecycle }
type App = { name: string; head: Summary; revision_count: number; active_revision_count: number }
type Revision = Summary & { name: string; source_toml: string; definition: unknown; published_at: string; published_by: string }
type Preview = { definition: unknown; digest: string; payment_mode: string }
const starter = 'name = "my-app"\nschema_version = 1\n\n[container]\nimage = "REPOSITORY@sha256:DIGEST"\n\n[resources.limits]\nmemory = "1GiB"\n\n[http]\nport = 8080\n'

export function Catalog({ session, authorityFailure }: { session: Session; authorityFailure: (error: APIError) => void }) {
  const [apps, setApps] = useState<App[]>([])
  const [mode, setMode] = useState('offchain')
  const [nextApp, setNextApp] = useState<string | null>(null)
  const [selectedApp, setSelectedApp] = useState<App | null>(null)
  const [history, setHistory] = useState<Summary[]>([])
  const [nextRevision, setNextRevision] = useState<number | null>(null)
  const [selected, setSelected] = useState<Revision | null>(null)
  const [editing, setEditing] = useState(false)
  const [creating, setCreating] = useState(false)
  const [expectedHead, setExpectedHead] = useState<string | null>(null)
  const [source, setSource] = useState('')
  const [preview, setPreview] = useState<Preview | null>(null)
  const [problem, setProblem] = useState('')
  const [fields, setFields] = useState<APIError['fields']>([])
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [conflict, setConflict] = useState(false)
  const epoch = useRef(0)
  const serial = useRef<Record<string, number>>({})
  const controllers = useRef(new Set<AbortController>())
  const draft = useRef(0)
  const changing = useRef(false)
  const failure = useRef(authorityFailure)
  failure.current = authorityFailure

  function cancel() { epoch.current++; controllers.current.forEach(c => c.abort()); controllers.current.clear(); changing.current = false }
  // Resource generations are separate from capability polling and draft edits.
  async function run<T>(key: string, operation: (signal: AbortSignal) => Promise<T>, apply: (value: T) => void) {
    const e = epoch.current, ticket = (serial.current[key] || 0) + 1
    serial.current[key] = ticket
    const controller = new AbortController(); controllers.current.add(controller)
    const current = () => e === epoch.current && ticket === serial.current[key] && !controller.signal.aborted
    try { const value = await operation(controller.signal); if (current()) apply(value) }
    catch (error) {
      if (!current()) return
      if (error instanceof APIError && [401, 403, 503].includes(error.status)) { cancel(); failure.current(error); return }
      setProblem(error instanceof Error ? error.message : 'Catalog request failed.')
      setFields(error instanceof APIError ? error.fields : [])
      setConflict(error instanceof APIError && error.code === 'stale_head')
    } finally {
      controllers.current.delete(controller)
      if (current() && key === 'mutation') { changing.current = false; setBusy(false) }
    }
  }
  function loadApps(after?: string) {
    void run('list', signal => api<{ apps: App[]; payment_mode: string; next_after_name: string | null }>(session, '/api/admin/apps' + (after ? `?after_name=${encodeURIComponent(after)}` : ''), { signal }), data => {
      setApps(old => after ? [...old, ...data.apps.filter(a => !old.some(b => b.name === a.name))] : data.apps)
      setMode(data.payment_mode); setNextApp(data.next_after_name)
    })
  }
  function loadHistory(name: string, before?: number, rebase = false) {
    void run('history', signal => api<{ app: App; revisions: Summary[]; next_before_revision: number | null; payment_mode: string }>(session, `/api/admin/apps/${encodeURIComponent(name)}` + (before ? `?before_revision=${before}` : ''), { signal }), data => {
      setSelectedApp(data.app); setHistory(old => before ? [...old, ...data.revisions] : data.revisions); setNextRevision(data.next_before_revision); setMode(data.payment_mode)
      if (rebase) { setExpectedHead(data.app.head.revision_id); setPreview(null); setConflict(false); setMessage('Publication base refreshed. Validate the draft again.') }
    })
  }
  function inspect(name: string, id: string) {
    serial.current.validation = (serial.current.validation || 0) + 1; serial.current.detail = (serial.current.detail || 0) + 1; serial.current.history = (serial.current.history || 0) + 1
    setSelected(null); setSelectedApp(null); setHistory([]); setEditing(false); setExpectedHead(null); setSource(''); setPreview(null); setFields([]); setProblem(''); setConflict(false); draft.current++
    loadHistory(name)
    void run('detail', signal => api<Revision>(session, `/api/admin/apps/${encodeURIComponent(name)}/revisions/${id}`, { signal }), setSelected)
  }
  useEffect(() => {
    changing.current = false; setBusy(false); loadApps()
    return cancel
    // Same-account renewal preserves state but invalidates every old-token callback.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.access_token, session.user.id])

  function edit(create: boolean) {
    if (!create && (!selected || !selectedApp)) return
    serial.current.detail = (serial.current.detail || 0) + 1; serial.current.validation = (serial.current.validation || 0) + 1; serial.current.history = (serial.current.history || 0) + 1
    setCreating(create); setEditing(true); setSource(create ? starter : selected?.source_toml || '')
    setExpectedHead(create ? null : selectedApp!.head.revision_id)
    setPreview(null); setFields([]); setProblem(''); setMessage(''); setConflict(false); draft.current++
  }
  function validate() {
    const version = draft.current; setMessage(''); setProblem(''); setFields([]); setPreview(null)
    void run('validation', signal => api<Preview>(session, '/api/admin/apps/validate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, signal, body: JSON.stringify({ source_toml: source }) }), data => { if (version === draft.current) { setPreview(data); setMode(data.payment_mode) } })
  }
  function publish() {
    if (changing.current || !preview || (!creating && (!selectedApp || !expectedHead))) return
    changing.current = true; setBusy(true); setMessage(''); setProblem(''); setFields([])
    const name = selectedApp?.name
    const path = creating ? '/api/admin/apps' : `/api/admin/apps/${encodeURIComponent(name!)}/revisions`
    const body = { source_toml: source, ...(creating ? {} : { expected_head_revision_id: expectedHead }) }
    void run('mutation', signal => api<{ revision: Revision; changed: boolean }>(session, path, { method: 'POST', signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }), data => {
      setSelected(data.revision); setSelectedApp(null); setHistory([]); setNextRevision(null); setEditing(false); setSource(''); setPreview(null)
      setMessage(data.changed ? 'Revision published.' : data.revision.lifecycle.retired_at ? 'Identical content already exists as a retired revision.' : 'Identical content already exists. No new revision was created.')
      loadApps(); loadHistory(data.revision.name)
    })
  }
  function retire() {
    if (!selected || changing.current) return
    changing.current = true; setBusy(true); setMessage(''); setProblem('')
    void run('mutation', signal => api<{ revision: Revision; changed: boolean }>(session, `/api/admin/apps/${encodeURIComponent(selected.name)}/revisions/${selected.revision_id}/retire`, { method: 'POST', signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ expected_state_version: selected.lifecycle.version }) }), data => {
      setSelected(data.revision); setMessage(data.changed ? 'Revision retired. Existing assignments remain available.' : 'Revision was already retired.'); loadApps(); loadHistory(data.revision.name)
    })
  }
  return <div className="app-catalog" aria-labelledby="catalog-title">
    <div className="section-heading"><div><h3 id="catalog-title">App catalog</h3><p className="muted">Registry pricing policy: {mode}. Revisions are immutable.</p></div><div className="catalog-actions"><button className="button" disabled={busy} onClick={() => loadApps()}>Refresh catalog</button><button className="button lime" disabled={busy} onClick={() => edit(true)}>Create app</button></div></div>
    {problem && <div role="alert" className="notice error">{problem}{fields.length > 0 && <ul>{fields.map((f, i) => <li key={i}><code>{f.path}</code>: {f.message}</li>)}</ul>}</div>}
    {message && <div role="status" className="notice success">{message}</div>}
    <ul className="catalog-list">{apps.map(app => <li key={app.name}><button className="button" disabled={busy} onClick={() => inspect(app.name, app.head.revision_id)}>{app.name}</button><span>Revision {app.head.revision} · version {app.head.app_version || '(unversioned)'} · {app.active_revision_count} active</span></li>)}</ul>
    {nextApp && <button className="button" onClick={() => loadApps(nextApp)}>More apps</button>}
    {selectedApp && <div className="catalog-history"><h4>{selectedApp.name}: revision history</h4>{history.map(r => <button className="button" key={r.revision_id} disabled={busy} onClick={() => inspect(selectedApp.name, r.revision_id)}>Revision {r.revision}{r.lifecycle.retired_at ? ' (retired)' : ''}</button>)}{nextRevision && <button className="button" onClick={() => loadHistory(selectedApp.name, nextRevision)}>Older revisions</button>}</div>}
    {selected && !editing && <div className="catalog-detail"><h4>{selected.name} / revision {selected.revision}{selected.lifecycle.retired_at ? ' (retired)' : ''}</h4><code className="catalog-digest">{selected.digest}</code><p className="muted">Published {new Date(selected.published_at).toLocaleString()} by {selected.published_by}</p><div className="catalog-actions"><button className="button" disabled={busy || !selectedApp} onClick={() => edit(false)}>Publish new revision</button><button className="button" disabled={busy || !!selected.lifecycle.retired_at} onClick={retire}>Retire revision</button></div><h4>Original TOML</h4><pre>{selected.source_toml}</pre><h4>Normalized definition</h4><pre>{JSON.stringify(selected.definition, null, 2)}</pre></div>}
    {editing && conflict && selectedApp && <button className="button" onClick={() => loadHistory(selectedApp.name, undefined, true)}>Refresh publication base</button>}
    {editing && <div className="catalog-editor"><label htmlFor="app-source">{creating ? 'New app TOML' : 'New revision TOML'}</label><textarea id="app-source" spellCheck={false} value={source} disabled={busy} onChange={event => { setSource(event.target.value); draft.current++; serial.current.validation = (serial.current.validation || 0) + 1; setPreview(null); setFields([]) }} /><p className="muted">Image settings may be inherited; execution must be non-root. Replicas default to one. Multiple replicas mainly serve capacity-one instances, depending on reuse speed.</p><div className="catalog-actions"><button className="button" disabled={busy} onClick={validate}>Validate definition</button><button className="button lime" disabled={busy || !preview || (!creating && !expectedHead)} onClick={publish}>Publish definition</button><button className="button" disabled={busy} onClick={() => { draft.current++; serial.current.validation = (serial.current.validation || 0) + 1; setSource(''); setPreview(null); setFields([]); setEditing(false) }}>Cancel edit</button></div>{preview && <div><h4>Validated definition</h4><code className="catalog-digest">{preview.digest}</code><pre>{JSON.stringify(preview.definition, null, 2)}</pre></div>}</div>}
  </div>
}
