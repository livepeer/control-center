import { useEffect, useRef, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { api } from './api'
import { AppSecretAccess, appReferences } from './app-secret-access'
import type { AppAccess, OperatorApp } from './app-secret-access'
import { b64, saveServicePin, sealUploadKey, servicePin, verifyServiceResponse } from './secret-crypto'
import type { ServiceTrust } from './secret-crypto'

type Secret = { owner_id: string; secret_id: string; name: string; key: string; version_id: string; revision: number; deleted: boolean }
type App = OperatorApp
async function serviceRequest<T>(session: Session, origin: string, path: string, options: RequestInit, enrollment = false): Promise<T> {
 const url = new URL(path, origin)
 if (url.origin !== new URL(origin).origin || (url.protocol !== 'https:' && !['localhost','127.0.0.1'].includes(url.hostname))) throw new Error('The secrets service requires an HTTPS origin.')
 const pin = servicePin(origin)
 if (!pin && !enrollment) throw new Error('Generate an enrollment command in this browser to trust the secrets service first.')
 url.searchParams.set('nonce', b64(crypto.getRandomValues(new Uint8Array(32))))
 const headers = new Headers(options.headers); headers.set('Authorization', `Bearer ${session.access_token}`); headers.set('Content-Type','application/json')
 const method = options.method ?? 'GET', request = typeof options.body === 'string' ? options.body : ''
 const response = await fetch(url, {...options, method, headers, credentials:'omit', cache:'no-store', redirect:'error'})
 const raw = await response.text()
 if (pin) await verifyServiceResponse(pin, url, method, headers.get('Authorization')!, request, response, raw)
 const body = JSON.parse(raw)
 if (!response.ok) throw new Error(typeof body.code === 'string' ? body.code.replaceAll('_',' ') : 'Secrets service unavailable.')
 if (enrollment) {
  const trust = body.service as ServiceTrust
  if (!trust || new URL(trust.origin).origin !== url.origin) throw new Error('Invalid secrets service enrollment identity.')
  await verifyServiceResponse(trust, url, method, headers.get('Authorization')!, request, response, raw)
  saveServicePin(trust)
 }
 return body as T
}
export function secretsAPI<T>(session: Session, origin: string, path: string, options: RequestInit = {}): Promise<T> {
 return serviceRequest<T>(session, origin, path, options)
}
export function enrollSecretsService<T>(session: Session, origin: string): Promise<T> {
 return serviceRequest<T>(session, origin, '/v1/enrollment-grants', {method:'POST'}, true)
}
export function enrollmentEnvelope(control: string, setup: string): string {
 return 'lpcc1.' + b64(new TextEncoder().encode(JSON.stringify({version:1, control, setup}))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')
}
export async function encryptSecret(binding: Secret, value: string) {
 const bytes = new TextEncoder().encode(value)
 if (bytes.length > 65536 || value.includes('\0')) throw new Error('Use a UTF-8 value up to 64 KiB without NUL characters.')
 const raw = crypto.getRandomValues(new Uint8Array(32)), nonce = crypto.getRandomValues(new Uint8Array(12))
 const key = await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt'])
 const aad = new TextEncoder().encode(JSON.stringify([1,binding.owner_id,binding.secret_id,binding.name,binding.key,binding.version_id]))
 const encrypted = await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},key,bytes)
 bytes.fill(0)
 return {dataKey:raw, nonce:b64(nonce),ciphertext:b64(new Uint8Array(encrypted))}
}
export function OperatorSecrets({session, origin}:{session:Session;origin:string}) {
 const [secrets,setSecrets]=useState<Secret[]>([]),[apps,setApps]=useState<App[]>([])
 const [appName,setAppName]=useState(''),[access,setAccess]=useState<AppAccess|null>(null)
 const [name,setName]=useState(''),[key,setKey]=useState(''),[value,setValue]=useState(''),[problem,setProblem]=useState(''),[loadProblem,setLoadProblem]=useState(''),[message,setMessage]=useState(''),[busy,setBusy]=useState(false)
 const refreshGeneration=useRef(0)
 const refresh=async()=>{
  const generation=++refreshGeneration.current
  const [s,a,p]=await Promise.allSettled([servicePin(origin)?secretsAPI<{secrets:Secret[]}>(session,origin,'/v1/secrets'):Promise.resolve({secrets:[]}),api<{apps:App[]}>(session,'/api/operator/apps'),servicePin(origin)?secretsAPI<AppAccess>(session,origin,'/v1/app-approvals'):Promise.resolve(null)])
  if(generation!==refreshGeneration.current)return
  setSecrets(s.status==='fulfilled'?s.value.secrets:[])
  setApps(a.status==='fulfilled'?a.value.apps:[])
  setAccess(p.status==='fulfilled'?p.value:null)
  setLoadProblem(s.status==='rejected'?'Could not load secrets.':a.status==='rejected'?'Could not load app access.':p.status==='rejected'?'Could not load secret access.':'')
 }
 useEffect(()=>{const load=()=>{void refresh().catch(()=>setLoadProblem('Could not load operator secrets.'))};load();window.addEventListener('lpcc-secrets-enrolled',load);return()=>{refreshGeneration.current++;window.removeEventListener('lpcc-secrets-enrolled',load)}},[session.access_token,origin])
 const perform=async(fn:()=>Promise<void>)=>{setBusy(true);setProblem('');setMessage('');let failure='';try{await fn()}catch(e){failure=e instanceof Error?e.message:'Operation failed.'}finally{await refresh();if(failure)setProblem(failure);setBusy(false)}}
 async function save(event: React.FormEvent) { event.preventDefault()
  const draft={appName,name,key,value,generation:access?.generation}
  if(draft.appName&&draft.generation===undefined)return
  await perform(async()=>{
  const current=secrets.find(s=>!s.deleted&&s.name===draft.name&&s.key===draft.key)
  const binding=await secretsAPI<Secret>(session,origin,'/v1/secrets/reserve',{method:'POST',body:JSON.stringify({name:draft.name,key:draft.key,expected_revision:current?.revision??0})})
  const encrypted=await encryptSecret(binding,draft.value)
  try{const serviceKey=await secretsAPI<{public_key:string}>(session,origin,'/v1/encryption-key')
   const sealedKey=await sealUploadKey(servicePin(origin)!.origin,binding,serviceKey.public_key,encrypted.dataKey)
   const wrapped=await secretsAPI<{wrapped_key:string}>(session,origin,`/v1/secrets/${binding.secret_id}/wrap`,{method:'POST',body:JSON.stringify({version_id:binding.version_id,sealed_key:sealedKey})})
   await secretsAPI(session,origin,`/v1/secrets/${binding.secret_id}`,{method:'PUT',body:JSON.stringify({owner_id:binding.owner_id,secret_id:binding.secret_id,name:binding.name,key:binding.key,version_id:binding.version_id,nonce:encrypted.nonce,ciphertext:encrypted.ciphertext,wrapped_key:wrapped.wrapped_key,...(draft.appName?{app_name:draft.appName,expected_approval_generation:draft.generation}:{})})})
  } finally {encrypted.dataKey.fill(0);setValue('')}
  setMessage('Saved. Affected apps will rotate automatically; inspect machine status for completion.')
 })}
 return <section className="machines-section" aria-label="Operator secrets"><div className="section-heading"><div><h2>Secrets and app access</h2><p className="muted">Secrets belong to your workspace. Choose an app when saving to grant access across its revisions.</p></div></div>
 {(problem||loadProblem)&&<div className="notice error" role="alert">{problem||loadProblem}</div>}{message&&<div className="notice success" role="status">{message}</div>}
 <form onSubmit={save} className="machine-panel" style={{padding:24}}><label>App<select aria-label="App" value={appName} disabled={busy} onChange={event=>{const selected=event.target.value;setAppName(selected);const ref=apps.find(app=>app.name===selected);const first=ref&&appReferences(ref)[0];if(first){setName(first.secret);setKey(first.key)}}}><option value="">Workspace only; keep app access unchanged</option>{apps.map(app=><option key={app.name} value={app.name}>{app.name}</option>)}</select></label><label>Secret name<input disabled={busy} required pattern="lp-app-[a-z0-9][a-z0-9-]*" placeholder="lp-app-provider" value={name} onChange={e=>setName(e.target.value)}/></label><label>Key<input disabled={busy} required placeholder="api-key" value={key} onChange={e=>setKey(e.target.value)}/></label><label>Value<input disabled={busy} type="password" required autoComplete="off" value={value} onChange={e=>setValue(e.target.value)}/></label><button className="button primary" disabled={busy||!!appName&&!access}>Save secret</button></form>
 <div className="machine-panel table-scroll"><table><thead><tr><th>SECRET</th><th>KEY</th><th>USED BY</th><th>STATE</th><th/></tr></thead><tbody>{secrets.map(s=><tr key={s.secret_id}><td>{s.name}</td><td>{s.key}</td><td>{apps.filter(a=>a.secrets.some(r=>r.secret===s.name&&r.key===s.key)).map(a=>a.name).join(', ')||'No app declarations'}</td><td>{s.deleted?'Deleted; runtime cleanup may be pending':s.version_id?'Available':'Awaiting value'}</td><td>{!s.deleted&&<button className="button" disabled={busy} onClick={()=>void perform(async()=>{await secretsAPI(session,origin,`/v1/secrets/${s.secret_id}`,{method:'DELETE',body:JSON.stringify({expected_revision:s.revision})});setMessage('Deletion accepted. Dependent apps will drain; offline machines remain pending.')})}>Delete</button>}</td></tr>)}</tbody></table></div>
 <AppSecretAccess session={session} origin={origin} apps={apps} access={access} secrets={secrets.filter(secret=>!secret.deleted&&!!secret.version_id).map(secret=>({secret:secret.name,key:secret.key}))} busy={busy} perform={perform} />
 </section>
}
