import {useEffect, useRef, useState} from 'react'
import type {Session} from '@supabase/supabase-js'
import {api} from './api'
import {secretsAPI} from './operator-secrets'
import {servicePin} from './secret-crypto'

type Reference = {name:string; secret:string; key:string}
type Revision = {revision_id:string; digest:string; name:string; revision:number; app_version:string; schema_version:number; canonical_format:string; definition:{container:{image:string; secrets:Reference[]}}}
export type OperatorApp = {name:string; aliases?:{name:string}[]; denied:boolean; generation:number; secrets:Reference[]; machines?:string[]; requested_machines?:string[]; revisions?:Revision[]}
type Access = {generation:number; apps:{name:string; denied:boolean; approvals:{revision_id:string; digest:string; references:Reference[]}[]}[]}
type Review = {app:OperatorApp; revision:Revision; generation:number}

export function AppSecretAccess({session,origin,apps,refreshApps}:{session:Session;origin:string;apps:OperatorApp[];refreshApps:()=>Promise<void>}) {
 const [access,setAccess]=useState<Access|null>(null),[review,setReview]=useState<Review|null>(null)
 const [busy,setBusy]=useState(false),[problem,setProblem]=useState(''),[loadProblem,setLoadProblem]=useState(''),[message,setMessage]=useState('')
 const current=useRef(0),changing=useRef(false)
 async function refresh() {
  const version=++current.current
  setAccess(null);setReview(null)
  if(!servicePin(origin)){setLoadProblem('');return}
  try {
   const data=await secretsAPI<Access>(session,origin,'/v1/app-approvals')
   if(version===current.current){setAccess(data);setLoadProblem('')}
  } catch(error){if(version===current.current)setLoadProblem(error instanceof Error?error.message:'Could not load approvals.')}
 }
 useEffect(()=>{void refresh();return()=>{current.current++}},[session.access_token,origin,apps])
 async function change(fn:()=>Promise<void>) {
  if(changing.current)return
  changing.current=true;setBusy(true);setProblem('');setMessage('')
  try{await fn()}catch(error){setProblem(error instanceof Error?error.message:'Could not update access.')}
  finally{setReview(null);await refreshApps();await refresh();changing.current=false;setBusy(false)}
 }
 async function schedule(app:OperatorApp,denied:boolean) {
  if(app.denied===denied)return
  await api(session,`/api/operator/apps/${encodeURIComponent(app.name)}/policy`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({denied,expected_generation:app.generation})})
 }
 async function deny(app:OperatorApp) {
  if(!access)return
  const generation=access.generation
  await change(async()=>{
   await secretsAPI(session,origin,`/v1/app-approvals/${encodeURIComponent(app.name)}`,{method:'PUT',body:JSON.stringify({denied:true,expected_generation:generation})})
   try{await schedule(app,true)}catch{throw new Error('Secret access revoked. Could not update scheduling; refresh and retry Deny.')}
   setMessage('Secret access revoked. App instances will drain; offline machines remain pending.')
  })
 }
 async function approve() {
  if(!review)return
  const decision=review
  await change(async()=>{
   await secretsAPI(session,origin,`/v1/app-approvals/${encodeURIComponent(decision.app.name)}`,{method:'PUT',body:JSON.stringify({denied:false,expected_generation:decision.generation,revision:decision.revision})})
   setMessage('Revision approved. Renewed approvals wait for previous instances to drain. Use Allow scheduling to resume a denied app.')
  })
 }
 const approved=(app:OperatorApp,revision:Revision)=>access?.apps.some(a=>a.name===app.name&&!a.denied&&a.approvals.some(grant=>grant.revision_id===revision.revision_id&&grant.digest===revision.digest))
 return <>
  <h3>App access</h3><p className="muted">Secret access requires approval for each exact revision and its declared references. Deny revokes approvals and drains the app. Deny scheduling stops the app while keeping its secret approvals.</p>
  {!servicePin(origin)&&<p>Generate an enrollment command in this browser to manage secret approvals.</p>}
  {(problem||loadProblem)&&<div className="notice error" role="alert">{problem||loadProblem}</div>}{message&&<div className="notice success" role="status">{message}</div>}
  <div className="machine-panel table-scroll"><table aria-label="App access"><thead><tr><th>App</th><th>Aliases</th><th>Revisions and secret access</th><th>Machines</th><th>Scheduling</th><th>Actions</th></tr></thead><tbody>{apps.map(app=><tr key={app.name}>
   <td>{app.name}</td><td>{app.aliases?.map(alias=>alias.name).join(', ')||'None'}</td>
   <td>{app.revisions?.map(revision=><div key={revision.revision_id}>
    <p>Revision {revision.revision}: <code>{revision.revision_id}</code><br/><code>{revision.digest}</code></p>
    <p>{revision.definition.container.secrets.map(ref=>`${ref.secret}/${ref.key} → ${ref.name}`).join(', ')||'No secret references'}</p>
    <p>{revision.definition.container.secrets.length===0?'No secret approval needed':!access?'Approval status unavailable':approved(app,revision)?'Approved':'Approval required'}</p>
    {revision.definition.container.secrets.length>0&&<button className="button" disabled={busy||!access} onClick={()=>setReview({app,revision:structuredClone(revision),generation:access!.generation})}>Review revision {revision.revision}</button>}
   </div>)||'Revision details unavailable'}</td>
   <td>{app.machines?.join(', ')||((app.requested_machines?.length??0)>0?'Assigned; stopped':'None')}</td><td>{app.denied?'Denied; enforcement may be pending':'Allowed'}</td>
   <td><button className="button" disabled={busy||!access} onClick={()=>void deny(app)}>Deny</button>{!app.denied&&<button className="button" disabled={busy} onClick={()=>void change(async()=>{await schedule(app,true);setMessage('Scheduling denied. Secret approvals are unchanged; use Deny to revoke them when the secrets service is available.')})}>Deny scheduling</button>}{app.denied&&<button className="button" disabled={busy} onClick={()=>void change(async()=>{await schedule(app,false);setMessage('Scheduling allowed. Secret approvals are still required.')})}>Allow scheduling</button>}</td>
  </tr>)}</tbody></table></div>
  {review&&<div className="machine-panel" role="dialog" aria-label="Approve revision secret access" style={{padding:24}}>
   <h4>Approve {review.app.name}, revision {review.revision.revision}</h4>
   <p>Revision: <code>{review.revision.revision_id}</code><br/>Digest: <code>{review.revision.digest}</code><br/>Image: <code>{review.revision.definition.container.image}</code></p>
   <ul>{review.revision.definition.container.secrets.map(ref=><li key={ref.name}><code>{ref.secret}/{ref.key} → {ref.name}</code></li>)}</ul>
   <details><summary>Full app definition</summary><pre style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{JSON.stringify(review.revision.definition,null,2)}</pre></details>
   <p>This revision may receive your stored values for these references on your assigned machines.</p>
   <button className="button primary" disabled={busy} onClick={()=>void approve()}>Approve this revision</button> <button className="button" disabled={busy} onClick={()=>setReview(null)}>Cancel</button>
  </div>}
 </>
}
