import { useEffect, useRef, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { api, APIError } from './api'

type Revision = { revision_id: string; digest: string; name: string; revision: number; app_version: string; lifecycle: { retired_at: string | null }; definition: { name: string; instances: { replicas: number } } }
type Summary = Pick<Revision, 'revision_id' | 'digest' | 'revision' | 'app_version' | 'lifecycle'>
type Assignment = { revision_id: string; digest: string; app_name: string; revision_number: number; generation: number; activation_generation: number; desired: 'present' | 'absent'; replicas?: number; revision?: Revision; start_after?: unknown; replacement?: unknown; start_allowed: boolean; completed_at: string | null; failure?: string; observed_at: string | null; created_at: string; actor_id: string }
type Listing = { assignments: Assignment[]; apps_generation: number; published_generation: number; delivery_error: string | null; next_after_revision_id: string | null; last_config_fetch_at: string | null }
type Detail = { assignment: Assignment; revision: Revision; history: Assignment[]; next_before_generation: number | null }

export function MachineApps({ session, machine, authorityFailure }: { session: Session; machine: { node_id: string; hostname: string; }; authorityFailure: (error: APIError) => void }) {
  const base = `/api/admin/machines/${machine.node_id}/apps`
  const [listing, setListing] = useState<Listing | null>(null)
  const [apps, setApps] = useState<{ name: string }[]>([])
  const [moreApps, setMoreApps] = useState<string | null>(null)
  const [appName, setAppName] = useState('')
  const [revisions, setRevisions] = useState<Summary[]>([])
  const [moreRevisions, setMoreRevisions] = useState<number | null>(null)
  const [selected, setSelected] = useState<Revision | null>(null)
  const [replicas, setReplicas] = useState(1)
  const [counts, setCounts] = useState<Record<string, { value: number; activation: number }>>({})
  const [detail, setDetail] = useState<Detail | null>(null)
  const [problem, setProblem] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const requestGeneration = useRef(0), serial = useRef<Record<string, number>>({}), changing = useRef(false)
  const controllers = useRef(new Set<AbortController>())
  const loadedPages = useRef(1), listingRequest = useRef<Promise<void> | null>(null)
  const failure = useRef(authorityFailure); failure.current = authorityFailure

  function cancel() { requestGeneration.current++; controllers.current.forEach(c => c.abort()); controllers.current.clear(); changing.current = false; listingRequest.current = null }
  async function run<T>(key: string, operation: (signal: AbortSignal) => Promise<T>, apply: (value: T) => void) {
    const e = requestGeneration.current, ticket = (serial.current[key] || 0) + 1; serial.current[key] = ticket
    const controller = new AbortController(); controllers.current.add(controller)
    const current = () => e === requestGeneration.current && ticket === serial.current[key] && !controller.signal.aborted
    try { const value = await operation(controller.signal); if (current()) apply(value) }
    catch (error) {
      if (!current()) return
      if (error instanceof APIError && [401, 403, 503].includes(error.status)) { cancel(); failure.current(error); return }
      setProblem(error instanceof Error ? error.message : 'Assignment request failed.')
    } finally { controllers.current.delete(controller); if (current() && key === 'mutation') { changing.current = false; setBusy(false) } }
  }
  function load(after?: string) {
    if (changing.current) return
    const request = run('list', async signal => {
      const page = (cursor?: string) => api<Listing>(session, base + '?limit=100' + (cursor ? `&after_revision_id=${cursor}` : ''), { signal })
      let data = await page(after)
      const assignments = [...data.assignments]
      for (let i = 1; !after && i < loadedPages.current && data.next_after_revision_id; i++) {
        data = await page(data.next_after_revision_id)
        assignments.push(...data.assignments)
      }
      return { ...data, assignments }
    }, data => {
      if (after) loadedPages.current++
      else setCounts(old => Object.fromEntries(Object.entries(old).filter(([id, draft]) => data.assignments.some(a => a.revision_id === id && a.desired === 'present' && a.activation_generation === draft.activation))))
      setListing(old => after && old ? { ...data, assignments: [...old.assignments, ...data.assignments.filter(a => !old.assignments.some(b => a.revision_id === b.revision_id))] } : data)
    })
    listingRequest.current = request
    void request.finally(() => { if (listingRequest.current === request) listingRequest.current = null })
  }
  function loadApps(after?: string) {
    void run('apps', signal => api<{ apps: { name: string }[]; next_after_name: string | null }>(session, '/api/admin/apps' + (after ? `?after_name=${encodeURIComponent(after)}` : ''), { signal }), data => { setApps(old => after ? [...old, ...data.apps] : data.apps); setMoreApps(data.next_after_name) })
  }
  function chooseApp(name: string, before?: number) {
    setAppName(name)
    if (!before) {
      serial.current.revision = (serial.current.revision || 0) + 1
      setSelected(null); setRevisions([]); setMoreRevisions(null)
    }
    if (!name) { serial.current.revisions = (serial.current.revisions || 0) + 1; return }
    void run('revisions', signal => api<{ revisions: Summary[]; next_before_revision: number | null }>(session, `/api/admin/apps/${encodeURIComponent(name)}` + (before ? `?before_revision=${before}` : ''), { signal }), data => {
      setRevisions(old => before ? [...old, ...data.revisions] : data.revisions); setMoreRevisions(data.next_before_revision)
      if (!before && data.revisions.length) chooseRevision(data.revisions[0].revision_id, name)
    })
  }
  function chooseRevision(id: string, name = appName) {
    setSelected(null)
    if (!id) { serial.current.revision = (serial.current.revision || 0) + 1; return }
    void run('revision', signal => api<Revision>(session, `/api/admin/apps/${encodeURIComponent(name)}/revisions/${id}`, { signal }), data => { setSelected(data); setReplicas(data.definition.instances.replicas) })
  }
  function inspect(id: string, before?: number) {
    if (!before) setDetail(null)
    void run('detail', signal => api<Detail>(session, `${base}/${id}` + (before ? `?before_generation=${before}` : ''), { signal }), data => setDetail(old => before && old ? { ...data, history: [...old.history, ...data.history] } : data))
  }
  useEffect(() => {
    setBusy(false); load(); loadApps()
    const timer = window.setInterval(() => { if (!document.hidden && !changing.current && !listingRequest.current) load() }, 5000)
    return () => { window.clearInterval(timer); cancel() }
    // The parent keys this component by account, machine and enrollment.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.access_token, machine.node_id])

  function mutate(path: string, method: string, body: unknown) {
    if (changing.current || !listing) return
    changing.current = true; setBusy(true); setProblem(''); setMessage('')
    listingRequest.current = null
    serial.current.list = (serial.current.list || 0) + 1; serial.current.detail = (serial.current.detail || 0) + 1
    void run('mutation', signal => api<{ assignments: Assignment[] }>(session, path, { method, signal, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }), data => {
      setCounts(old => Object.fromEntries(Object.entries(old).filter(([id]) => !data.assignments.some(a => a.revision_id === id))))
      changing.current = false; setMessage('Desired assignment saved. Runtime completion is pending.'); setDetail(null); load()
    })
  }
  function present(a: Assignment) { return a.desired === 'present' }
  function count(a: Assignment) { return counts[a.revision_id]?.activation === a.activation_generation ? counts[a.revision_id].value : a.replicas ?? 1 }
  function label(a: Assignment) {
    if (a.desired === 'absent') return a.completed_at ? 'Removed' : 'Removing — waiting for cleanup'
    if (a.start_after && !a.start_allowed) return 'Waiting for previous revision cleanup'
    if (a.failure && !a.completed_at) return `Failed: ${a.failure}`
    if (a.replacement && !a.completed_at) return 'Rolling replacement in progress'
    if (a.completed_at) return 'Applied — health unverified'
    return 'Pending Runtime completion'
  }
  const selectedAssignment = listing?.assignments.find(a => a.revision_id === selected?.revision_id)
  const validCount = (n: number) => Number.isInteger(n) && n >= 1 && n <= 100
  return <section className="machine-apps" aria-labelledby="machine-apps-title">
    <div className="section-heading"><div><h3 id="machine-apps-title">Apps on {machine.hostname}</h3><code>{machine.node_id}</code></div><button className="button" disabled={busy} onClick={() => { load(); loadApps(); if (appName) chooseApp(appName) }}>Refresh assignments</button></div>
    <p className="muted">Revisions stay pinned. Equal replica limits above one roll within the combined limit; other replacements wait for full cleanup. Applied means replica reconciliation completed; health, registration and discoverability are separate.</p>
    {problem && <div role="alert" className="notice error">{problem}</div>}{message && <div role="status" className="notice success">{message}</div>}
    {listing && <p className="muted">Desired app generation {listing.apps_generation}; published {listing.published_generation}. Last config request: {listing.last_config_fetch_at ? new Date(listing.last_config_fetch_at).toLocaleString() : 'None'}{listing.delivery_error ? ` · Delivery failed: ${listing.delivery_error}` : ''}</p>}
    <div className="catalog-actions">
      <label>Catalog app <select aria-label="Catalog app for machine" value={appName} disabled={busy} onChange={e => chooseApp(e.target.value)}><option value="">Choose an app</option>{apps.map(a => <option key={a.name}>{a.name}</option>)}</select></label>
      <label>Revision <select aria-label="Catalog revision for machine" value={selected?.revision_id || ''} disabled={busy || !appName} onChange={e => chooseRevision(e.target.value)}><option value="">Choose a revision</option>{revisions.map(r => <option key={r.revision_id} value={r.revision_id}>Revision {r.revision} · version {r.app_version || '(unversioned)'}{r.lifecycle.retired_at ? ' (retired)' : ''}</option>)}</select></label>
      <label>Replicas <input aria-label="New assignment replicas" type="number" min="1" max="100" value={replicas} disabled={busy} onChange={e => setReplicas(Number(e.target.value))} /></label>
      <button className="button lime" disabled={busy || !listing || !selected || !!selected.lifecycle.retired_at || !validCount(replicas) || !!(selectedAssignment && (present(selectedAssignment) || !selectedAssignment.completed_at))} onClick={() => selected && mutate(`${base}/${selected.revision_id}`, 'PUT', { digest: selected.digest, expected_generation: selectedAssignment?.generation || 0, replicas })}>Assign selected revision</button>
      {moreApps && <button className="button" disabled={busy} onClick={() => loadApps(moreApps)}>More catalog apps</button>}{moreRevisions && <button className="button" disabled={busy} onClick={() => chooseApp(appName, moreRevisions)}>Older catalog revisions</button>}
    </div>
    {selected && <details><summary>Inspect selected revision</summary><code>{selected.digest}</code><pre>{JSON.stringify(selected.definition, null, 2)}</pre></details>}
    <ul className="catalog-list">{listing?.assignments.map(a => <li key={a.revision_id}>
      <div><strong>{a.app_name} / revision {a.revision_number}</strong><p>{label(a)}</p><code>{a.revision_id}</code><p className="muted">Desired {a.generation} · activation {a.activation_generation}{a.observed_at ? ` · last observation ${new Date(a.observed_at).toLocaleString()}` : ''}</p></div>
      <div className="catalog-actions"><button className="button" disabled={busy} onClick={() => inspect(a.revision_id)}>Inspect assignment {a.revision_id}</button>
        {present(a) && <><label>Replicas <input aria-label={`Replicas for ${a.revision_id}`} type="number" min="1" max="100" value={count(a)} disabled={busy} onChange={e => setCounts(old => ({ ...old, [a.revision_id]: { value: Number(e.target.value), activation: a.activation_generation } }))} /></label><button className="button" disabled={busy || !validCount(count(a))} onClick={() => mutate(`${base}/${a.revision_id}`, 'PUT', { digest: a.digest, expected_generation: a.generation, replicas: count(a) })}>Save replicas</button>
        <button className="button" disabled={busy} onClick={() => mutate(`${base}/${a.revision_id}`, 'DELETE', { expected_generation: a.generation })}>Remove revision {a.revision?.revision}</button>
        <button className="button" disabled={busy || !selected || selected.revision_id === a.revision_id || selected.name !== a.revision?.name || !!selected.lifecycle.retired_at || !validCount(replicas) || !!(a.start_after && !a.start_allowed) || !!(selectedAssignment && (present(selectedAssignment) || !selectedAssignment.completed_at))} onClick={() => selected && mutate(`${base}/${a.revision_id}/replace`, 'POST', { expected_generation: a.generation, target: { revision_id: selected.revision_id, digest: selected.digest, expected_generation: selectedAssignment?.generation || 0, replicas } })}>Replace revision {a.revision?.revision}</button></>}
      </div>
    </li>)}</ul>
    {listing?.assignments.length === 0 && <p>No app assignments.</p>}{listing?.next_after_revision_id && <button className="button" disabled={busy} onClick={() => load(listing.next_after_revision_id!)}>More assignments</button>}
    {detail && <div className="catalog-detail"><h4>Assignment history: {detail.revision.name} / revision {detail.revision.revision}</h4><pre>{JSON.stringify(detail.revision.definition, null, 2)}</pre><ul>{detail.history.map(a => <li key={a.generation}>Generation {a.generation} · {a.desired} · {a.replicas || 0} replicas · {a.actor_id} · {new Date(a.created_at).toLocaleString()} · {a.completed_at ? 'Completed' : 'Uncompleted'}</li>)}</ul>{detail.next_before_generation && <button className="button" onClick={() => inspect(detail.assignment.revision_id, detail.next_before_generation!)}>Older assignment changes</button>}</div>}
  </section>
}
