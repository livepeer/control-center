import { Fragment, useEffect, useRef, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { api as requestAPI, APIError } from './api'
import { b64, saveServicePin, sealUploadKey, servicePin, verifyServiceResponse } from './secret-crypto'
import type { ServiceTrust } from './secret-crypto'

type Secret = { orchestrator_address: string; secret_id: string; name: string; key: string; version_id: string; revision: number; deleted: boolean }
type Reference = { name: string; secret: string; key: string }
type App = { name: string; aliases?: {name: string}[]; denied: boolean; generation: number; secrets: Reference[]; catalog_secrets?: Reference[]; machines?: string[]; requested_machines?: string[] }
type Editor = { scope: 'group' | 'inventory'; name: string; key: string; secret?: Secret; action: 'save' | 'delete' }

function references(app: App): Reference[] {
 return [...app.secrets, ...(app.catalog_secrets ?? [])]
}
function declarationSources(app: App, name: string, key?: string): string {
 const matches = (ref: Reference) => ref.secret === name && (key === undefined || ref.key === key)
 const sources = []
 if ((app.catalog_secrets ?? app.secrets).some(matches)) sources.push('Latest catalog')
 if (((app.requested_machines?.length ?? 0) > 0 || (app.machines?.length ?? 0) > 0) && app.secrets.some(matches)) sources.push('Machine revisions')
 return sources.join(' · ')
}
async function serviceRequest<T>(session: Session, origin: string, address: string, path: string, options: RequestInit, enrollment = false): Promise<T> {
 const url = new URL(path, origin)
 if (url.origin !== new URL(origin).origin || (url.protocol !== 'https:' && !['localhost','127.0.0.1'].includes(url.hostname))) throw new Error('The secrets service requires an HTTPS origin.')
 options.signal?.throwIfAborted()
 url.searchParams.set('orchestrator_address', address)
 const pin = servicePin(origin)
 if (!pin && !enrollment) throw new Error('Generate an enrollment command in this browser to trust the secrets service first.')
 url.searchParams.set('nonce', b64(crypto.getRandomValues(new Uint8Array(32))))
 const headers = new Headers(options.headers); headers.set('Authorization', `Bearer ${session.access_token}`); headers.set('Content-Type','application/json')
 const method = options.method ?? 'GET', request = typeof options.body === 'string' ? options.body : ''
 const response = await fetch(url, {...options, method, headers, credentials:'omit', cache:'no-store', redirect:'error'})
 const raw = await response.text()
 if (pin) await verifyServiceResponse(pin, url, method, headers.get('Authorization')!, request, response, raw)
 const body = JSON.parse(raw)
 options.signal?.throwIfAborted()
 if (!response.ok) throw new APIError(response.status, body.code === 'secret_limit_reached' ? 'This orchestrator has reached its limit of 100 secrets, including reserved and deleted entries.' : typeof body.code === 'string' ? body.code.replaceAll('_',' ') : 'Secrets service unavailable.',typeof body.code === 'string' ? body.code : '')
 if (enrollment) {
  const trust = body.service as ServiceTrust
  if (!trust || new URL(trust.origin).origin !== url.origin) throw new Error('Invalid secrets service enrollment identity.')
  await verifyServiceResponse(trust, url, method, headers.get('Authorization')!, request, response, raw)
  saveServicePin(trust)
 }
 return body as T
}
export function secretsAPI<T>(session: Session, origin: string, address: string, path: string, options: RequestInit = {}): Promise<T> {
 return serviceRequest<T>(session, origin, address, path, options)
}
export function enrollSecretsService<T>(session: Session, origin: string, address: string, signal?: AbortSignal): Promise<T> {
 return serviceRequest<T>(session, origin, address, '/v1/enrollment-grants', {method:'POST', signal}, true)
}
export function enrollmentEnvelope(control: string, setup: string): string {
 return 'lpcc1.' + b64(new TextEncoder().encode(JSON.stringify({version:1, control, setup}))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')
}
export async function encryptSecret(binding: Secret, value: string) {
 const bytes = new TextEncoder().encode(value)
 if (bytes.length > 65536 || value.includes('\0')) throw new Error('Use a UTF-8 value up to 64 KiB without NUL characters.')
 const raw = crypto.getRandomValues(new Uint8Array(32)), nonce = crypto.getRandomValues(new Uint8Array(12))
 const key = await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt'])
 const aad = new TextEncoder().encode(JSON.stringify([1,binding.orchestrator_address,binding.secret_id,binding.name,binding.key,binding.version_id]))
 const encrypted = await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},key,bytes)
 bytes.fill(0)
 return {dataKey:raw, nonce:b64(nonce),ciphertext:b64(new Uint8Array(encrypted))}
}
export function OperatorSecrets({session, origin, address, authorityFailure}: {session: Session; origin: string; address: string; authorityFailure: (error: unknown) => void}) {
 const controller = useRef(new AbortController())
 const signal = controller.current.signal
 const scoped = (path: string) => path + (path.includes('?') ? '&' : '?') + 'orchestrator_address=' + encodeURIComponent(address)
 const api = <T,>(session: Session, path: string, options: RequestInit = {}) => requestAPI<T>(session, scoped(path), {...options, signal})
 const request = <T,>(path: string, options: RequestInit = {}) => secretsAPI<T>(session, origin, address, path, {...options, signal})
 useEffect(() => () => controller.current.abort(), [])
 const [secrets, setSecrets] = useState<Secret[] | null>(null)
 const [apps, setApps] = useState<App[] | null>(null)
 const [appName, setAppName] = useState(''), [name, setName] = useState('')
 const [editor, setEditor] = useState<Editor | null>(null), [value, setValue] = useState('')
 const [problem, setProblem] = useState(''), [appProblem, setAppProblem] = useState(''), [secretsProblem, setSecretsProblem] = useState(''), [message, setMessage] = useState('')
 const loadProblem = [appProblem, secretsProblem].filter(Boolean).join(' ')
 const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false)
 const refreshGeneration = useRef(0), changing = useRef(false), contextGeneration = useRef(0)
 const trusted = !!servicePin(origin)
 const refresh = async () => {
  const generation = ++refreshGeneration.current
  setLoading(true)
  const [s, a] = await Promise.allSettled([
   servicePin(origin) ? request<{secrets: Secret[]}>('/v1/secrets') : Promise.resolve(null),
   api<{apps: App[]}>(session, '/api/operator/apps'),
  ])
  if (signal.aborted || generation !== refreshGeneration.current) return
  // Retain the last successful data on failure, but disable mutations until a fresh read succeeds.
  if (s.status === 'fulfilled') setSecrets(s.value?.secrets ?? null)
  if (a.status === 'fulfilled') setApps(a.value.apps)
  if (s.status === 'rejected') authorityFailure(s.reason)
  if (a.status === 'rejected') authorityFailure(a.reason)
  setSecretsProblem(s.status === 'rejected' ? 'Could not load secrets.' : '')
  setAppProblem(a.status === 'rejected' ? 'Could not load app access.' : '')
  setLoading(false)
 }
 useEffect(() => {
  setSecrets(null); setApps(null); setEditor(null); setValue(''); setProblem(''); setMessage(''); setBusy(false); changing.current = false
  const load = () => { void refresh() }
  load()
  window.addEventListener('lpcc-secrets-enrolled', load)
  return () => { refreshGeneration.current++; contextGeneration.current++; window.removeEventListener('lpcc-secrets-enrolled', load) }
 }, [session.access_token, origin, address])

 const selectedApp = apps?.find(app => app.name === appName)
 const groups = selectedApp ? [...new Set(references(selectedApp).map(ref => ref.secret))].sort() : []
 const groupKeys = name ? [...new Set([
  ...(selectedApp ? references(selectedApp).filter(ref => ref.secret === name).map(ref => ref.key) : []),
  ...(secrets ?? []).filter(secret => secret.name === name).map(secret => secret.key),
 ])].sort() : []
 const canManage = trusted && secrets !== null && apps !== null && !loading && !loadProblem && !busy
 const stored = (group: string, key: string) => secrets?.find(s => s.name === group && s.key === key && !s.deleted)
 const declared = (group: string, key: string) => (apps ?? []).some(app => references(app).some(ref => ref.secret === group && ref.key === key))
 const editable = (draft: Editor) => !!(stored(draft.name, draft.key) || declared(draft.name, draft.key)) && (draft.scope !== 'group' || groupKeys.includes(draft.key))
 const consumers = (group: string, key: string) => (apps ?? []).filter(app => references(app).some(ref => ref.secret === group && ref.key === key)).map(app => app.name)
 const clearEditor = () => { setEditor(null); setValue('') }
 useEffect(() => {
  if (!apps) return
  if (appName && !selectedApp) { setAppName(''); setName(''); clearEditor() }
  else if (name && !groups.includes(name)) { setName(''); clearEditor() }
  else if (editor?.action === 'save' && !editable(editor)) clearEditor()
 }, [apps, secrets, appName, name, editor])

 async function perform(fn: (current: () => boolean) => Promise<void>) {
  if (changing.current) return
  changing.current = true; setBusy(true); setProblem(''); setMessage('')
  const context = contextGeneration.current
  const current = () => !signal.aborted && context === contextGeneration.current
  try { await fn(current) }
  catch (error) {
   if (signal.aborted) return
   authorityFailure(error)
   if (!current()) return
   const text = error instanceof Error ? error.message : 'Operation failed.'
   if (text === 'secret conflict') {
    clearEditor()
    setProblem('This entry changed. Review the refreshed entries and choose an action again.')
   } else setProblem(text)
  } finally {
   if (current()) {
    setValue('')
    await refresh()
    if (current()) { changing.current = false; setBusy(false) }
   }
  }
 }
 function begin(scope: Editor['scope'], group: string, key: string, action: Editor['action']) {
  setValue(''); setProblem(''); setMessage('')
  setEditor({scope, name: group, key, secret: stored(group, key), action})
 }
 async function save(event: React.FormEvent) {
  event.preventDefault()
  if (!editor || !canManage) return
  if (!editable(editor)) { clearEditor(); return }
  const draft = editor
  await perform(async current => {
   if (new TextEncoder().encode(value).length > 65536 || value.includes('\0')) throw new Error('Use a UTF-8 value up to 64 KiB without NUL characters.')
   const binding = await request<Secret>('/v1/secrets/reserve', {method: 'POST', body: JSON.stringify({name: draft.name, key: draft.key, expected_revision: draft.secret?.revision ?? 0})})
   if (!current()) return
   if (binding.orchestrator_address !== address) throw new Error('Secret belongs to a different orchestrator.')
   // A failed first upload can leave a reservation. Retrying it must use its revision.
   setEditor({...draft, secret: {...binding, version_id: draft.secret?.version_id ?? ''}})
   const encrypted = await encryptSecret(binding, value)
   try {
    if (!current()) return
    const serviceKey = await request<{public_key: string}>('/v1/encryption-key')
    if (!current()) return
    const sealedKey = await sealUploadKey(servicePin(origin)!.origin, binding, serviceKey.public_key, encrypted.dataKey)
    if (!current()) return
    const wrapped = await request<{wrapped_key: string}>(`/v1/secrets/${binding.secret_id}/wrap`, {method: 'POST', body: JSON.stringify({version_id: binding.version_id, sealed_key: sealedKey})})
    if (!current()) return
    await request(`/v1/secrets/${binding.secret_id}`, {method: 'PUT', body: JSON.stringify({orchestrator_address: binding.orchestrator_address, secret_id: binding.secret_id, name: binding.name, key: binding.key, version_id: binding.version_id, nonce: encrypted.nonce, ciphertext: encrypted.ciphertext, wrapped_key: wrapped.wrapped_key})})
   } finally { encrypted.dataKey.fill(0) }
   if (!current()) return
   clearEditor()
   setMessage('Saved. Affected apps will rotate automatically; inspect machine status for completion.')
  })
 }
 async function remove() {
  if (!editor?.secret || !canManage) return
  const secret = editor.secret
  await perform(async current => {
   await request(`/v1/secrets/${secret.secret_id}`, {method: 'DELETE', body: JSON.stringify({expected_revision: secret.revision})})
   if (!current()) return
   clearEditor()
   setMessage('Deletion accepted. Dependent apps will drain; offline machines remain pending.')
  })
 }
 function entries(group: string, keys: string[], scope: Editor['scope']) {
  return <div className="table-scroll"><table className="secret-entries" aria-label={`${scope === 'group' ? 'Keys in' : 'Workspace keys in'} ${group}`}>
   <thead><tr><th>Key</th><th>Environment variables</th><th>State</th><th>Used by apps</th><th>Actions</th></tr></thead>
   <tbody>{keys.map(key => {
    const secret = stored(group, key)
    const destinations = [...new Set((scope === 'group' && selectedApp ? references(selectedApp) : (apps ?? []).flatMap(references)).filter(ref => ref.secret === group && ref.key === key).map(ref => ref.name))]
    const usedBy = consumers(group, key)
    const editing = editor?.scope === scope && editor.name === group && editor.key === key
    const deleted = secrets?.some(s => s.name === group && s.key === key && s.deleted)
    return <Fragment key={key}>
     <tr><td><code>{key}</code>{scope === 'group' && selectedApp && <small>{declarationSources(selectedApp, group, key) || 'Stored key; not declared by this app'}</small>}</td>
      <td>{apps === null ? 'Unavailable' : destinations.join(', ') || 'Not declared'}</td>
      <td>{secret ? secret.version_id ? 'Value stored' : 'Awaiting value' : deleted ? 'Deleted' : 'Missing value'}</td>
      <td>{apps === null ? 'Unavailable' : usedBy.join(', ') || 'No app declarations'}</td>
      <td><div className="secret-actions">
       {(secret || declared(group, key)) && <button className="button" disabled={!canManage} onClick={() => begin(scope, group, key, 'save')}>{secret?.version_id ? 'Replace value' : 'Add value'}</button>}
       {secret && <button className="button" disabled={!canManage} onClick={() => begin(scope, group, key, 'delete')}>Delete value</button>}
      </div></td>
     </tr>
     {editing && <tr><td colSpan={5} className="secret-editor-cell"><div className="secret-editor">
      <h4>{editor.action === 'delete' ? 'Delete value' : secret?.version_id ? 'Replace value' : 'Add value'}: <code>{group} / {key}</code></h4>
      <p>{usedBy.length ? `Affected apps: ${usedBy.join(', ')}.` : 'No apps currently declare this entry.'} {editor.action === 'delete' ? 'Deleting this value stops dependent app instances; offline machines may take longer.' : 'Saving changes this entry for every app that requests it. Stored values remain hidden.'}</p>
      {editor.action === 'save' ? <form onSubmit={save}>
       <label>Value<input type="password" required autoComplete="new-password" autoFocus disabled={!canManage} value={value} onChange={event => setValue(event.target.value)} /></label>
       <div className="secret-actions"><button type="submit" className="button primary" disabled={!canManage}>{busy ? 'Saving…' : 'Save value'}</button><button type="button" className="button" disabled={busy} onClick={clearEditor}>Cancel</button></div>
      </form> : <div className="secret-actions"><button className="button" disabled={!canManage} onClick={() => void remove()}>{busy ? 'Deleting…' : 'Confirm delete'}</button><button className="button" disabled={busy} onClick={clearEditor}>Cancel</button></div>}
     </div></td></tr>}
    </Fragment>
   })}</tbody>
  </table></div>
 }
 const inventoryGroups = [...new Set((secrets ?? []).map(secret => secret.name))].sort()
 return <section className="machines-section operator-secrets" aria-label="Operator secrets">
  <div className="section-heading"><div><h2>Secrets and app access</h2><p className="muted">Choose an app and secret group, then manage its key/value entries. Values stay hidden.</p></div><button className="button" disabled={busy || loading} onClick={() => void refresh()}>Refresh secrets</button></div>
  {loadProblem && <div className="notice error" role="alert">{loadProblem} Refresh to try again.</div>}
  {problem && <div className="notice error" role="alert">{problem}</div>}
  {message && <div className="notice success" role="status">{message}</div>}
  {!trusted && <p className="notice">Generate an enrollment command above in this browser to trust the secrets service before managing values.</p>}
  {loading && <p className="secret-note" aria-live="polite">Loading apps and secret entries…</p>}
  <div className="machine-panel secret-browser">
   <div className="secret-selectors">
    <label>App name<select aria-label="App name" value={appName} disabled={busy || loading || !apps || !!appProblem} onChange={event => {setAppName(event.target.value); setName(''); clearEditor(); setProblem(''); setMessage('')}}><option value="">Choose an app</option>{(apps ?? []).map(app => <option key={app.name} value={app.name}>{app.name}</option>)}</select></label>
    <label>Secret name<select aria-label="Secret name" value={name} disabled={busy || loading || !selectedApp || !groups.length || !!appProblem} onChange={event => {setName(event.target.value); clearEditor(); setProblem(''); setMessage('')}}><option value="">Choose a secret group</option>{groups.map(group => <option key={group} value={group}>{group} — {declarationSources(selectedApp!, group)}</option>)}</select></label>
   </div>
   {!loading && !appProblem && apps?.length === 0 && <p className="secret-note">No apps are available.</p>}
   {!loading && !appProblem && selectedApp && !groups.length && <p className="secret-note">This app does not declare any secrets.</p>}
   {!appName && !!apps?.length && <p className="secret-note">Select an app to see the secret groups it declares.</p>}
   {selectedApp && !!groups.length && !name && <p className="secret-note">Select a secret group to manage its keys.</p>}
   {name && selectedApp && <>
    <div className="secret-group-heading"><h3>{name}</h3><p>{declarationSources(selectedApp, name)}</p>
     {secrets !== null && !loadProblem && !loading && <p>{secrets.some(secret => secret.name === name && !secret.deleted) ? 'Using the existing matching workspace group.' : 'This group is missing. Saving its first key/value entry creates it.'}</p>}
    </div>
    {secrets !== null && entries(name, groupKeys, 'group')}
   </>}
  </div>
  <details className="machine-panel secret-inventory" onToggle={event => {if (!event.currentTarget.open && editor?.scope === 'inventory') clearEditor()}}>
   <summary>Workspace inventory</summary><p className="secret-note">All stored groups, including keys no app currently declares.</p>
   {secrets !== null ? inventoryGroups.length ? inventoryGroups.map(group => <div key={group} className="secret-inventory-group"><h3>{group}</h3>{entries(group, [...new Set(secrets.filter(secret => secret.name === group).map(secret => secret.key))].sort(), 'inventory')}</div>) : !loading && !loadProblem && <p className="secret-note">No workspace secret entries yet.</p> : <p className="secret-note">{trusted ? 'Secret entries have not loaded.' : 'Trust the secrets service to load workspace entries.'}</p>}
  </details>
  <h3 className="secret-access-heading">App access</h3><p className="secret-note">Apps are allowed by default. Denying an app drains all its revisions on your machines.</p>
  <div className="machine-panel table-scroll"><table className="secret-access" aria-label="App access"><thead><tr><th>App</th><th>Aliases</th><th>Declared secrets</th><th>Machines</th><th>Policy</th><th>Actions</th></tr></thead><tbody>{(apps ?? []).map(app => <tr key={app.name}><td>{app.name}</td><td>{app.aliases?.map(alias => alias.name).join(', ') || 'None'}</td><td>{[...new Set(references(app).map(ref => `${ref.secret}/${ref.key} → ${ref.name}`))].join(', ') || 'None'}</td><td>{app.machines?.join(', ') || ((app.requested_machines?.length ?? 0) > 0 ? 'Assigned; stopped' : 'None')}</td><td>{app.denied ? 'Denied; enforcement may be pending' : 'Allowed'}</td><td><button className="button" disabled={busy || loading || !!appProblem} onClick={() => void perform(async () => {await api(session, `/api/operator/apps/${encodeURIComponent(app.name)}/policy`, {method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({denied: !app.denied, expected_generation: app.generation})})})}>{app.denied ? 'Allow' : 'Deny'}</button></td></tr>)}</tbody></table></div>
 </section>
}
