import type {Session} from '@supabase/supabase-js'
import {api} from './api'
import {secretsAPI} from './operator-secrets'

export type Reference = {secret:string; key:string}
export type OperatorApp = {name:string; aliases?:{name:string}[]; denied:boolean; generation:number; secrets:(Reference & {name:string})[]; catalog_secrets?:(Reference & {name:string})[]; machines?:string[]; requested_machines?:string[]}
export type AppAccess = {generation:number; apps:{name:string; denied:boolean; approvals:{scope:string; secrets:Reference[]; generation:number}[]}[]}
export function appReferences(app:OperatorApp):Reference[] {
 return [...app.secrets,...(app.catalog_secrets??[])].filter((ref,index,all)=>all.findIndex(other=>other.secret===ref.secret&&other.key===ref.key)===index).map(ref=>({secret:ref.secret,key:ref.key}))
}
export function appGrant(access:AppAccess|null,name:string) {
 return access?.apps.find(app=>app.name===name&&!app.denied)?.approvals.find(grant=>grant.scope==='app-secrets'&&grant.generation>0)
}
export function AppSecretAccess({session,origin,apps,access,secrets,busy,perform}:{session:Session;origin:string;apps:OperatorApp[];access:AppAccess|null;secrets:Reference[];busy:boolean;perform:(fn:()=>Promise<void>)=>Promise<void>}) {
 async function schedule(app:OperatorApp,denied:boolean) {
  if(app.denied===denied)return
  await api(session,`/api/operator/apps/${encodeURIComponent(app.name)}/policy`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({denied,expected_generation:app.generation})})
 }
 async function grant(app:OperatorApp,ref:Reference) {
  if(!access)return
  const generation=access.generation
  await perform(async()=>{await secretsAPI(session,origin,`/v1/app-approvals/${encodeURIComponent(app.name)}`,{method:'PUT',body:JSON.stringify({expected_generation:generation,secrets:[ref]})})})
 }
 async function deny(app:OperatorApp) {
  if(!access)return
  const generation=access.generation
  await perform(async()=>{
   await secretsAPI(session,origin,`/v1/app-approvals/${encodeURIComponent(app.name)}`,{method:'PUT',body:JSON.stringify({denied:true,expected_generation:generation})})
   try{await schedule(app,true)}catch{throw new Error('Secret access revoked. Could not update scheduling; refresh and retry Deny.')}
  })
 }
 return <>
  <h3>App access</h3><p className="muted">Saving a secret for an app grants that app access across revisions. Deny revokes secret access and drains the app. Deny scheduling keeps secret approvals.</p>
  <div className="machine-panel table-scroll"><table aria-label="App access"><thead><tr><th>App</th><th>Aliases</th><th>Secret access</th><th>Machines</th><th>Scheduling</th><th>Actions</th></tr></thead><tbody>{apps.map(app=>{
   const approved=appGrant(access,app.name)
   return <tr key={app.name}>
    <td>{app.name}</td><td>{app.aliases?.map(alias=>alias.name).join(', ')||'None'}</td>
    <td>{appReferences(app).map(ref=>{
     const allowed=approved?.secrets.some(secret=>secret.secret===ref.secret&&secret.key===ref.key)
     const stored=secrets.some(secret=>secret.secret===ref.secret&&secret.key===ref.key)
     return <div key={`${ref.secret}/${ref.key}`}><code>{ref.secret}/{ref.key}</code><p>{!access?'Access status unavailable':allowed?'Access granted':stored?'Stored; access not granted':'Save a value to grant access'}</p>{stored&&!allowed&&<button className="button" disabled={busy||!access} onClick={()=>void grant(app,ref)}>Grant access to {ref.secret}/{ref.key}</button>}</div>
    })}{appReferences(app).length===0&&'No secret references'}</td>
    <td>{app.machines?.join(', ')||((app.requested_machines?.length??0)>0?'Assigned; stopped':'None')}</td><td>{app.denied?'Denied; enforcement may be pending':'Allowed'}</td>
    <td><button className="button" disabled={busy||!access} onClick={()=>void deny(app)}>Deny</button>{app.denied?<button className="button" disabled={busy} onClick={()=>void perform(async()=>{await schedule(app,false)})}>Allow scheduling</button>:<button className="button" disabled={busy} onClick={()=>void perform(async()=>{await schedule(app,true)})}>Deny scheduling</button>}</td>
   </tr>
  })}</tbody></table></div>
 </>
}
