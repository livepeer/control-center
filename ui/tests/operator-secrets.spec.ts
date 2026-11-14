import {test,expect} from '@playwright/test'
import type {Page} from '@playwright/test'
import {createHash,generateKeyPairSync,sign,webcrypto} from 'node:crypto'
import {readFileSync} from 'node:fs'
import {Aes256Gcm,CipherSuite,HkdfSha256} from '@hpke/core'
import {DhkemX25519HkdfSha256} from '@hpke/dhkem-x25519'

const vector=JSON.parse(readFileSync(new URL('../../secrets/testdata/hpke.json',import.meta.url),'utf8'))
const suite=()=>new CipherSuite({kem:new DhkemX25519HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes256Gcm()})
const info=(direction:string,origin=vector.origin)=>Buffer.from(JSON.stringify(['lpcc-data-key-v1',direction,origin,vector.binding.owner_id,vector.binding.secret_id,vector.binding.name,vector.binding.key,vector.binding.version_id]))
const hash=(s:string)=>createHash('sha256').update(s).digest('hex')

test('hpke-js opens Go standard-library delivery ciphertext',async()=>{
 const hpke=suite(),sealed=Buffer.from(vector.go_delivery,'base64')
 const key=await hpke.open({recipientKey:await hpke.kem.deserializePrivateKey(Buffer.from(vector.private_key,'base64')),enc:sealed.subarray(0,32),info:info('delivery')},sealed.subarray(32))
 expect(Buffer.from(key).toString('base64')).toBe(vector.data_key)
})

test('uploads hide data keys from the HTTPS edge and refuse service-key substitution',async({page})=>{
 const origin='https://SECRETS.test:443'
 const owner=vector.binding.owner_id,expiry=Math.floor(Date.now()/1000)+3600
 const session={access_token:`e30.${Buffer.from(JSON.stringify({exp:expiry})).toString('base64url')}.fixture`,refresh_token:'fixture',token_type:'bearer',expires_at:expiry,expires_in:3600,user:{id:owner,email:'owner@example.invalid',aud:'authenticated',role:'authenticated',app_metadata:{},user_metadata:{},created_at:'2026-11-06T00:00:00Z'}}
 await page.addInitScript(s=>localStorage.setItem('sb-auth-auth-token',JSON.stringify(s)),session)
 await page.route('http://auth.test/**',r=>r.fulfill({json:session.user,headers:{'Access-Control-Allow-Origin':'*'}}))
 const secret={...vector.binding,revision:1,deleted:false}
 const identity=generateKeyPairSync('ed25519'),substitute=generateKeyPairSync('ed25519')
 const trust={origin,public_key:identity.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')}
 const mainRequests:string[]=[],secretRequests:string[]=[]
 let releaseInitialApps=()=>{},appReads=0
 const initialApps=new Promise<void>(resolve=>{releaseInitialApps=resolve})
 let denied=false,reserved=false,failWrap=true,tamperKey=true,replacePin=false,wrapCalls=0
 let dek:Buffer|undefined,encrypted:Record<string,string>|undefined
 await page.route('**/api/**',async route=>{
  const req=route.request();mainRequests.push(req.postData()||'')
  switch(new URL(req.url()).pathname){
   case '/api/config':return route.fulfill({json:{supabase_url:'http://auth.test',supabase_publishable_key:'fixture'}})
   case '/api/operator/config':expect(req.headers().authorization).toBe(`Bearer ${session.access_token}`);return route.fulfill({json:{public_api_url:'https://api.example',secrets_url:origin}})
   case '/api/bootstrap-token':return route.fulfill({json:{token:'control.grant.signature',expires_at:new Date(expiry*1000).toISOString()}})
   case '/api/machines':return route.fulfill({json:{machines:[]}})
   case '/api/me':return route.fulfill({json:{user_id:owner,is_admin:false}})
   case '/api/operator/apps':if(appReads++===0){await initialApps;return route.fulfill({status:503,json:{error:'unavailable'}})}return route.fulfill({json:{apps:[{name:'provider',aliases:[{name:'provider-alias'}],secrets:[{name:'API_TOKEN',secret:secret.name,key:secret.key}],machines:['owner-machine'],denied,generation:denied?1:0}]}})
   case '/api/operator/apps/provider/policy':denied=req.postDataJSON().denied;return route.fulfill({json:{generation:1}})
   default:return route.fulfill({status:404,json:{error:'unexpected'}})
  }
 })
 await page.route('https://secrets.test/**',async route=>{
  const req=route.request(),url=new URL(req.url()),path=url.pathname
  const headers={'Access-Control-Allow-Origin':'http://localhost:5173','Access-Control-Allow-Headers':'authorization,content-type','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS','Access-Control-Expose-Headers':'X-Livepeer-Service-Signature'}
  if(req.method()==='OPTIONS')return route.fulfill({status:204,headers})
  secretRequests.push(req.postData()||'')
  const reply=(body:unknown,status=200,key=identity.privateKey)=>{
   const raw=JSON.stringify(body),digest=hash(JSON.stringify([req.method(),path+url.search,hash(req.postData()||'')]))
   const proof=JSON.stringify(['lpcc-secrets-response-v1',origin,digest,hash(req.headers().authorization||''),status,hash(raw)])
   return route.fulfill({status,body:raw,contentType:'application/json',headers:{...headers,'X-Livepeer-Service-Signature':sign(null,Buffer.from(proof),key).toString('base64')}})
  }
  if(path==='/v1/enrollment-grants')return reply({token:'setup.grant.signature',expires_at:new Date(expiry*1000).toISOString(),service:replacePin?{...trust,public_key:substitute.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')}:trust},200,replacePin?substitute.privateKey:identity.privateKey)
  if(path==='/v1/encryption-key')return reply({public_key:vector.public_key},200,tamperKey?substitute.privateKey:identity.privateKey)
  if(path==='/v1/secrets')return reply({secrets:reserved?[secret]:[]})
  if(path==='/v1/secrets/reserve'){expect(req.postDataJSON().expected_revision).toBe(reserved?1:0);reserved=true;return reply(secret)}
  if(path.endsWith('/wrap')){
   wrapCalls++
   expect(req.postDataJSON()).not.toHaveProperty('data_key')
   const hpke=suite(),sealed=Buffer.from(req.postDataJSON().sealed_key,'base64')
   expect(sealed.length).toBe(80)
   dek=Buffer.from(await hpke.open({recipientKey:await hpke.kem.deserializePrivateKey(Buffer.from(vector.private_key,'base64')),enc:sealed.subarray(0,32),info:info('upload',origin)},sealed.subarray(32)))
   if(failWrap){failWrap=false;return reply({code:'key_unavailable'},503)}
   return reply({wrapped_key:'vault:v1:fixture'})
  }
  if(req.method()==='PUT'){encrypted=req.postDataJSON();return reply({revision:2})}
  return reply({error:'unexpected'},404)
 })
 await page.goto('/')
 await expect(page.getByRole('cell',{name:'provider-alias',exact:true})).toBeVisible()
 const command=page.getByLabel('Bootstrap command');await expect(command).toContainText('lpcc1.')
 const envelope=(await command.innerText()).match(/lpcc1\.([A-Za-z0-9_-]+)/)![1]
 expect(JSON.parse(Buffer.from(envelope,'base64url').toString())).toEqual({version:1,control:'control.grant.signature',setup:'setup.grant.signature'})
 const staleApps=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/operator/apps')
 releaseInitialApps();await (await staleApps).finished()
 await page.evaluate(()=>new Promise<void>(resolve=>requestAnimationFrame(()=>resolve())))
 await expect(page.getByRole('alert')).toHaveCount(0)
 await expect(page.getByRole('cell',{name:'provider-alias',exact:true})).toBeVisible()
 await page.getByRole('button',{name:'Deny',exact:true}).click()
 await expect(page.getByRole('button',{name:'Allow',exact:true})).toBeVisible()
 await page.getByLabel('App name',{exact:true}).selectOption('provider')
 await page.getByLabel('Secret name',{exact:true}).selectOption(secret.name)
 await page.getByRole('button',{name:'Add value',exact:true}).click()
 const save=async()=>{await page.getByLabel('Value',{exact:true}).fill('plaintext-sentinel');await page.getByRole('button',{name:'Save value',exact:true}).click()}
 await save()
 await expect(page.getByRole('alert')).toContainText('could not be authenticated')
 expect(wrapCalls).toBe(0)
 const refreshed=page.waitForResponse(r=>new URL(r.url()).pathname==='/v1/secrets')
 await page.evaluate(()=>window.dispatchEvent(new Event('lpcc-secrets-enrolled')))
 await (await refreshed).finished()
 await page.evaluate(()=>new Promise<void>(resolve=>requestAnimationFrame(()=>resolve())))
 await expect(page.getByRole('alert')).toContainText('could not be authenticated')
 tamperKey=false
 await save();await expect(page.getByRole('alert')).toContainText('key unavailable')
 await save();await expect(page.getByRole('status')).toContainText('Saved.')
 expect(mainRequests.join(' ')).not.toContain('plaintext-sentinel');expect(mainRequests.join(' ')).not.toContain('setup.grant.signature')
 expect(encrypted).toBeDefined();expect(dek).toBeDefined()
 expect(secretRequests.join(' ')).not.toContain('plaintext-sentinel');expect(secretRequests.join(' ')).not.toContain(dek!.toString('base64'))
 const key=await webcrypto.subtle.importKey('raw',dek!,'AES-GCM',false,['decrypt'])
 const aad=Buffer.from(JSON.stringify([1,owner,secret.secret_id,secret.name,secret.key,secret.version_id]))
 const plain=await webcrypto.subtle.decrypt({name:'AES-GCM',iv:Buffer.from(encrypted!.nonce,'base64'),additionalData:aad},key,Buffer.from(encrypted!.ciphertext,'base64'))
 expect(Buffer.from(plain).toString()).toBe('plaintext-sentinel');await expect(page.getByLabel('Value',{exact:true})).toHaveCount(0)
 replacePin=true
 await page.getByRole('button',{name:'Refresh token'}).click()
 await expect(page.getByRole('alert')).toContainText('could not be authenticated')
 expect(await page.evaluate(origin=>JSON.parse(localStorage.getItem(`lpcc-secrets-service:${origin}`)!).public_key,vector.origin)).toBe(trust.public_key)
})

type FixtureReference = {name: string; secret: string; key: string}
type FixtureApp = {name: string; secrets: FixtureReference[]; catalog_secrets: FixtureReference[]; machines: string[]; requested_machines: string[]; denied: boolean; generation: number}
type FixtureSecret = {owner_id: string; secret_id: string; name: string; key: string; version_id: string; revision: number; deleted: boolean}
const group = 'lp-app-provider'
const reference = (key = 'api-key', secret = group, name = 'API_TOKEN') => ({name, secret, key})

async function operatorFixture(page: Page, trusted = true) {
 const origin = 'https://secrets.test', owner = vector.binding.owner_id, expiry = Math.floor(Date.now()/1000)+3600
 const identity = generateKeyPairSync('ed25519')
 const trust = {origin, public_key: identity.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')}
 const session = {access_token:`e30.${Buffer.from(JSON.stringify({exp:expiry})).toString('base64url')}.fixture`, refresh_token:'fixture', token_type:'bearer', expires_at:expiry, expires_in:3600, user:{id:owner, email:'owner@example.invalid', aud:'authenticated', role:'authenticated', app_metadata:{}, user_metadata:{}, created_at:'2026-11-06T00:00:00Z'}}
 const secret = (name: string, key: string, id: string): FixtureSecret => ({owner_id:owner, secret_id:id, name, key, version_id:'stored-version', revision:2, deleted:false})
 const state = {
  apps: [
   {name:'provider', secrets:[reference(), reference('token','lp-app-old','OLD_TOKEN')], catalog_secrets:[reference(), reference('api-key',group,'SECOND_TOKEN'), reference('account-id',group,'ACCOUNT_ID'), reference('region','lp-app-new','REGION')], machines:['owner-machine'], requested_machines:['owner-machine'], denied:false, generation:0},
   {name:'worker', secrets:[reference('api-key',group,'WORKER_TOKEN')], catalog_secrets:[reference('api-key',group,'WORKER_TOKEN')], machines:[], requested_machines:[], denied:false, generation:0},
   {name:'no-secrets', secrets:[], catalog_secrets:[], machines:[], requested_machines:[], denied:false, generation:0},
  ] as FixtureApp[],
  secrets: [
   {...secret(group,'api-key','deleted-history'), deleted:true, version_id:'', revision:3},
   secret(group,'api-key','active-key'),
   secret(group,'unused-key','unused-key'),
   secret('lp-app-orphan','token','orphan-key'),
  ],
  mutations: [] as {path: string; method: string; body: Record<string, unknown>}[],
  failApps:false, failSecrets:false, failEnrollment:!trusted,
  secretReadGate:undefined as Promise<void> | undefined,
  reserveGate:undefined as Promise<void> | undefined,
 }
 await page.addInitScript(({session,trust,trusted}) => {
  localStorage.setItem('sb-auth-auth-token',JSON.stringify(session))
  if (trusted) localStorage.setItem(`lpcc-secrets-service:${trust.origin}`,JSON.stringify(trust))
 }, {session,trust,trusted})
 await page.route('http://auth.test/**',route => route.fulfill({json:session.user,headers:{'Access-Control-Allow-Origin':'*'}}))
 await page.route('**/api/**',async route => {
  const req = route.request(), path = new URL(req.url()).pathname
  switch (path) {
   case '/api/config':return route.fulfill({json:{supabase_url:'http://auth.test',supabase_publishable_key:'fixture'}})
   case '/api/operator/config':return route.fulfill({json:{public_api_url:'https://api.example',secrets_url:origin}})
   case '/api/bootstrap-token':return route.fulfill({json:{token:'control.grant.signature',expires_at:new Date(expiry*1000).toISOString()}})
   case '/api/machines':return route.fulfill({json:{machines:[]}})
   case '/api/me':return route.fulfill({json:{user_id:owner,is_admin:false}})
   case '/api/operator/apps':return route.fulfill(state.failApps ? {status:503,json:{error:'unavailable'}} : {json:{apps:state.apps}})
   case '/api/operator/apps/provider/policy': {
    state.apps[0].denied = req.postDataJSON().denied; state.apps[0].generation++
    return route.fulfill({json:{generation:state.apps[0].generation}})
   }
   default:return route.fulfill({status:404,json:{error:'unexpected'}})
  }
 })
 await page.route(`${origin}/**`,async route => {
  const req = route.request(), url = new URL(req.url()), path = url.pathname
  const headers = {'Access-Control-Allow-Origin':'http://localhost:5173','Access-Control-Allow-Headers':'authorization,content-type','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Expose-Headers':'X-Livepeer-Service-Signature'}
  if (req.method() === 'OPTIONS') return route.fulfill({status:204,headers})
  const reply = (body: unknown, status = 200) => {
   const raw = JSON.stringify(body), digest = hash(JSON.stringify([req.method(),path+url.search,hash(req.postData()||'')]))
   const proof = JSON.stringify(['lpcc-secrets-response-v1',origin,digest,hash(req.headers().authorization||''),status,hash(raw)])
   return route.fulfill({status,body:raw,contentType:'application/json',headers:{...headers,'X-Livepeer-Service-Signature':sign(null,Buffer.from(proof),identity.privateKey).toString('base64')}})
  }
  if (path === '/v1/enrollment-grants') return state.failEnrollment ? reply({code:'unavailable'},503) : reply({token:'setup.grant.signature',expires_at:new Date(expiry*1000).toISOString(),service:trust})
  if (path === '/v1/encryption-key') return reply({public_key:vector.public_key})
  if (path === '/v1/secrets') {
   const snapshot = JSON.parse(JSON.stringify(state.secrets))
   const gate = state.secretReadGate; state.secretReadGate = undefined
   if (gate) await gate
   return state.failSecrets ? reply({code:'unavailable'},503) : reply({secrets:snapshot})
  }
  const body = req.postDataJSON()
  state.mutations.push({path,method:req.method(),body})
  if (path === '/v1/secrets/reserve') {
   const gate = state.reserveGate; state.reserveGate = undefined
   if (gate) await gate
   let current = state.secrets.find(s => !s.deleted && s.name === body.name && s.key === body.key)
   if (body.expected_revision !== (current?.revision ?? 0)) return reply({code:'secret_conflict'},409)
   if (!current) {
    current = {...secret(body.name,body.key,`created-${state.mutations.length}`),version_id:'',revision:1}
    state.secrets.push(current)
   }
   return reply({...current,version_id:`version-${state.mutations.length}`})
  }
  if (path.endsWith('/wrap')) return reply({wrapped_key:'vault:v1:fixture'})
  const current = state.secrets.find(s => s.secret_id === path.split('/').pop())
  if (!current) return reply({code:'not_found'},404)
  if (req.method() === 'PUT') {
   current.version_id = body.version_id; current.revision++
   return reply({revision:current.revision})
  }
  if (req.method() === 'DELETE') {
   if (body.expected_revision !== current.revision) return reply({code:'secret_conflict'},409)
   current.deleted = true; current.version_id = ''; current.revision++
   return reply({deleted:true})
  }
  return reply({code:'unexpected'},404)
 })
 await page.goto('/')
 const section = page.getByRole('region',{name:'Operator secrets'})
 await expect(section).toBeVisible()
 if (trusted) await expect(page.getByLabel('Bootstrap command')).toContainText('lpcc1.')
 await expect(section.getByText('Loading apps and secret entries…')).toBeHidden()
 return {state,section}
}

test('app and group selectors combine catalog and machine declarations and reuse matching groups',async ({page}) => {
 const {section} = await operatorFixture(page)
 await expect(section.getByLabel('Secret name',{exact:true})).toBeDisabled()
 await section.getByLabel('App name',{exact:true}).selectOption('provider')
 const groups = section.getByLabel('Secret name',{exact:true})
 await expect(groups.locator('option')).toHaveText(['Choose a secret group','lp-app-new — Latest catalog','lp-app-old — Machine revisions','lp-app-provider — Latest catalog · Machine revisions'])
 await groups.selectOption(group)
 await expect(section.getByText('Using the existing matching workspace group.')).toBeVisible()
 const keys = section.getByRole('table',{name:`Keys in ${group}`,exact:true})
 await expect(keys.getByRole('row')).toHaveCount(4)
 const live = keys.getByRole('row').filter({has:page.getByText('api-key',{exact:true})})
 await expect(live).toContainText('Value stored')
 await expect(live).toContainText('API_TOKEN, SECOND_TOKEN')
 await expect(live).toContainText('provider, worker')
 await expect(live.getByRole('button',{name:'Replace value',exact:true})).toBeVisible()
 await expect(keys.getByRole('row').filter({has:page.getByText('account-id',{exact:true})})).toContainText('Missing value')
 await expect(keys.getByRole('row').filter({has:page.getByText('unused-key',{exact:true})})).toContainText('Stored key; not declared by this app')
 await expect(section.getByLabel('Value',{exact:true})).toHaveCount(0)
 await section.getByLabel('App name',{exact:true}).selectOption('worker')
 await expect(groups.locator('option')).toHaveText(['Choose a secret group','lp-app-provider — Latest catalog'])
 await expect(groups).toHaveValue('')
 await section.getByLabel('App name',{exact:true}).selectOption('no-secrets')
 await expect(groups).toBeDisabled()
 await expect(section.getByText('This app does not declare any secrets.')).toBeVisible()
})

test('create, replace, delete and re-create individual values without changing declarations',async ({page}) => {
 const {state,section} = await operatorFixture(page)
 await section.getByLabel('App name',{exact:true}).selectOption('provider')
 await section.getByLabel('Secret name',{exact:true}).selectOption('lp-app-new')
 await expect(section.getByText('This group is missing. Saving its first key/value entry creates it.')).toBeVisible()
 await section.getByRole('button',{name:'Add value',exact:true}).click()
 await section.getByLabel('Value',{exact:true}).fill('new-region')
 await section.getByRole('button',{name:'Save value',exact:true}).click()
 await expect(section.getByRole('status')).toContainText('Saved.')
 expect(state.mutations[0].body).toEqual({name:'lp-app-new',key:'region',expected_revision:0})
 await expect(section.getByText('Using the existing matching workspace group.')).toBeVisible()
 await expect(section.getByLabel('Value',{exact:true})).toHaveCount(0)
 await section.getByLabel('Secret name',{exact:true}).selectOption(group)
 const keys = section.getByRole('table',{name:`Keys in ${group}`,exact:true})
 const live = keys.getByRole('row').filter({has:page.getByText('api-key',{exact:true})})
 await live.getByRole('button',{name:'Replace value',exact:true}).click()
 await expect(section.getByText(/Affected apps: provider, worker/)).toBeVisible()
 await expect(section.getByLabel('Value',{exact:true})).toHaveValue('')
 await section.getByLabel('Value',{exact:true}).fill('replacement-sentinel')
 await section.getByRole('button',{name:'Save value',exact:true}).click()
 await expect(section.getByRole('status')).toContainText('Saved.')
 expect(state.mutations.filter(m => m.path.endsWith('/reserve')).at(-1)?.body).toEqual({name:group,key:'api-key',expected_revision:2})
 await live.getByRole('button',{name:'Delete value',exact:true}).click()
 await expect(section.getByText(/Deleting this value stops dependent app instances/)).toContainText('provider, worker')
 expect(state.mutations.filter(m => m.method === 'DELETE')).toHaveLength(0)
 await section.getByRole('button',{name:'Cancel',exact:true}).click()
 await live.getByRole('button',{name:'Delete value',exact:true}).click()
 await section.getByRole('button',{name:'Confirm delete',exact:true}).click()
 await expect(section.getByRole('status')).toContainText('Deletion accepted.')
 expect(state.mutations.find(m => m.method === 'DELETE')).toMatchObject({path:'/v1/secrets/active-key',body:{expected_revision:3}})
 await expect(live).toContainText('Deleted')
 await live.getByRole('button',{name:'Add value',exact:true}).click()
 await section.getByLabel('Value',{exact:true}).fill('restored-sentinel')
 await section.getByRole('button',{name:'Save value',exact:true}).click()
 await expect(section.getByRole('status')).toContainText('Saved.')
 expect(state.mutations.filter(m => m.path.endsWith('/reserve')).at(-1)?.body).toEqual({name:group,key:'api-key',expected_revision:0})
 await expect(keys.getByRole('row').filter({has:page.getByText('account-id',{exact:true})})).toContainText('Missing value')
 expect(JSON.stringify(state.mutations)).not.toMatch(/new-region|replacement-sentinel|restored-sentinel/)
 await section.getByText('Workspace inventory',{exact:true}).click()
 const orphan = section.getByRole('table',{name:'Workspace keys in lp-app-orphan',exact:true})
 await orphan.getByRole('button',{name:'Replace value',exact:true}).click()
 await expect(section.getByText(/No apps currently declare this entry/)).toBeVisible()
 await section.getByLabel('Value',{exact:true}).fill('orphan-replacement')
 await section.getByRole('button',{name:'Save value',exact:true}).click()
 await expect(section.getByRole('status')).toContainText('Saved.')
 await orphan.getByRole('button',{name:'Delete value',exact:true}).click()
 await section.getByRole('button',{name:'Confirm delete',exact:true}).click()
 await expect(section.getByRole('status')).toContainText('Deletion accepted.')
 expect(state.secrets.find(s => s.secret_id === 'orphan-key')?.deleted).toBe(true)
})

test('editing clears values on cancellation and selection changes and preserves valid selections on refresh',async ({page}) => {
 const {section} = await operatorFixture(page)
 await section.getByLabel('App name',{exact:true}).selectOption('provider')
 await section.getByLabel('Secret name',{exact:true}).selectOption(group)
 const keys = section.getByRole('table',{name:`Keys in ${group}`,exact:true})
 const live = keys.getByRole('row').filter({has:page.getByText('api-key',{exact:true})})
 await live.getByRole('button',{name:'Replace value',exact:true}).click()
 await section.getByLabel('Value',{exact:true}).fill('cancelled')
 await section.getByRole('button',{name:'Cancel',exact:true}).click()
 await live.getByRole('button',{name:'Replace value',exact:true}).click()
 await expect(section.getByLabel('Value',{exact:true})).toHaveValue('')
 await section.getByLabel('Value',{exact:true}).fill('changed-group')
 await section.getByLabel('Secret name',{exact:true}).selectOption('lp-app-old')
 await expect(section.getByLabel('Value',{exact:true})).toHaveCount(0)
 await section.getByRole('button',{name:'Add value',exact:true}).click()
 await expect(section.getByLabel('Value',{exact:true})).toHaveValue('')
 await section.getByLabel('Value',{exact:true}).fill('changed-app')
 await section.getByLabel('App name',{exact:true}).selectOption('worker')
 await expect(section.getByLabel('Value',{exact:true})).toHaveCount(0)
 await section.getByLabel('Secret name',{exact:true}).selectOption(group)
 await section.getByRole('button',{name:'Refresh secrets',exact:true}).click()
 await expect(section.getByText('Loading apps and secret entries…')).toBeHidden()
 await expect(section.getByLabel('App name',{exact:true})).toHaveValue('worker')
 await expect(section.getByLabel('Secret name',{exact:true})).toHaveValue(group)
})

test('revision conflicts require review and in-flight saves cannot be submitted twice',async ({page}) => {
 const {state,section} = await operatorFixture(page)
 await section.getByLabel('App name',{exact:true}).selectOption('provider')
 await section.getByLabel('Secret name',{exact:true}).selectOption(group)
 const live = section.getByRole('table',{name:`Keys in ${group}`,exact:true}).getByRole('row').filter({has:page.getByText('api-key',{exact:true})})
 await live.getByRole('button',{name:'Replace value',exact:true}).click()
 state.secrets.find(s => s.secret_id === 'active-key')!.revision++
 await section.getByLabel('Value',{exact:true}).fill('stale-edit')
 await section.getByRole('button',{name:'Save value',exact:true}).click()
 await expect(section.getByRole('alert')).toContainText('This entry changed.')
 await expect(section.getByLabel('Value',{exact:true})).toHaveCount(0)
 expect(state.mutations).toHaveLength(1)
 let release = () => {}
 state.reserveGate = new Promise<void>(resolve => {release = resolve})
 await live.getByRole('button',{name:'Replace value',exact:true}).click()
 await section.getByLabel('Value',{exact:true}).fill('current-edit')
 await section.getByRole('button',{name:'Save value',exact:true}).click()
 await expect(section.getByRole('button',{name:'Saving…',exact:true})).toBeDisabled()
 await expect(section.getByLabel('App name',{exact:true})).toBeDisabled()
 expect(state.mutations.filter(m => m.path.endsWith('/reserve'))).toHaveLength(2)
 release()
 await expect(section.getByRole('status')).toContainText('Saved.')
 expect(state.mutations.filter(m => m.path.endsWith('/reserve'))).toHaveLength(2)
 expect(state.mutations.filter(m => m.path.endsWith('/reserve')).at(-1)?.body.expected_revision).toBe(3)
})

test('failed refreshes retain metadata without presenting failures as missing entries',async ({page}) => {
 const {state,section} = await operatorFixture(page)
 await section.getByLabel('App name',{exact:true}).selectOption('provider')
 await section.getByLabel('Secret name',{exact:true}).selectOption(group)
 state.failSecrets = true
 await section.getByRole('button',{name:'Refresh secrets',exact:true}).click()
 await expect(section.getByRole('alert')).toContainText('Could not load secrets.')
 await expect(section.getByText('Value stored',{exact:true}).first()).toBeVisible()
 await expect(section.getByText('This group is missing. Saving its first key/value entry creates it.')).toHaveCount(0)
 await expect(section.getByRole('button',{name:'Replace value',exact:true}).first()).toBeDisabled()
 const policy = section.getByRole('table',{name:'App access',exact:true}).getByRole('row').filter({has:page.getByRole('cell',{name:'provider',exact:true})})
 await expect(policy.getByRole('button',{name:'Deny',exact:true})).toBeEnabled()
 await policy.getByRole('button',{name:'Deny',exact:true}).click()
 await expect(policy.getByRole('button',{name:'Allow',exact:true})).toBeEnabled()
 expect(state.apps[0].denied).toBe(true)
 await section.getByLabel('App name',{exact:true}).selectOption('no-secrets')
 await expect(section.getByText('This app does not declare any secrets.')).toBeVisible()
 await section.getByLabel('App name',{exact:true}).selectOption('provider')
 await section.getByLabel('Secret name',{exact:true}).selectOption(group)
 state.failSecrets = false; state.failApps = true
 await section.getByRole('button',{name:'Refresh secrets',exact:true}).click()
 await expect(section.getByRole('alert')).toContainText('Could not load app access.')
 await expect(section.getByLabel('App name',{exact:true})).toBeDisabled()
 await expect(policy.getByRole('button',{name:'Allow',exact:true})).toBeDisabled()
 state.failApps = false
 await section.getByRole('button',{name:'Refresh secrets',exact:true}).click()
 await expect(section.getByRole('alert')).toHaveCount(0)
 await expect(section.getByLabel('Secret name',{exact:true})).toHaveValue(group)
 await expect(section.getByRole('button',{name:'Replace value',exact:true}).first()).toBeEnabled()
})

test('a stale refresh cannot overwrite a newer successful read',async ({page}) => {
 const {state,section} = await operatorFixture(page)
 await section.getByLabel('App name',{exact:true}).selectOption('provider')
 await section.getByLabel('Secret name',{exact:true}).selectOption(group)
 let release = () => {}
 state.secretReadGate = new Promise<void>(resolve => {release = resolve})
 const staleRequest = page.waitForRequest(r => new URL(r.url()).pathname === '/v1/secrets')
 await section.getByRole('button',{name:'Refresh secrets',exact:true}).click()
 await staleRequest
 state.secrets.find(s => s.secret_id === 'active-key')!.deleted = true
 await page.evaluate(() => window.dispatchEvent(new Event('lpcc-secrets-enrolled')))
 const live = section.getByRole('table',{name:`Keys in ${group}`,exact:true}).getByRole('row').filter({has:page.getByText('api-key',{exact:true})})
 await expect(live).toContainText('Deleted')
 const staleResponse = page.waitForResponse(r => new URL(r.url()).pathname === '/v1/secrets')
 release(); await (await staleResponse).finished()
 await expect(live).toContainText('Deleted')
 await expect(live.getByRole('button',{name:'Add value',exact:true})).toBeEnabled()
})

test('untrusted browsers can browse declarations but cannot manage or infer stored values',async ({page}) => {
 const {section} = await operatorFixture(page,false)
 await expect(section.getByText(/Generate an enrollment command above/)).toBeVisible()
 await section.getByLabel('App name',{exact:true}).selectOption('provider')
 await section.getByLabel('Secret name',{exact:true}).selectOption(group)
 await expect(section.getByRole('table',{name:`Keys in ${group}`,exact:true})).toHaveCount(0)
 await expect(section.getByText('This group is missing. Saving its first key/value entry creates it.')).toHaveCount(0)
 await expect(section.getByRole('button',{name:'Add value',exact:true})).toHaveCount(0)
})

test('initial load failures and empty catalogs have distinct states',async ({page}) => {
 const {state,section} = await operatorFixture(page)
 state.failSecrets = true
 await page.reload()
 await expect(section.getByRole('alert')).toContainText('Could not load secrets.')
 await section.getByText('Workspace inventory',{exact:true}).click()
 await expect(section.getByText('Secret entries have not loaded.')).toBeVisible()
 await expect(section.getByText('No workspace secret entries yet.')).toHaveCount(0)
 state.apps = []
 await section.getByRole('button',{name:'Refresh secrets',exact:true}).click()
 await expect(section.getByText('No apps are available.')).toBeVisible()
 state.failSecrets = false; state.failApps = true
 await page.reload()
 await expect(section.getByRole('alert')).toContainText('Could not load app access.')
 await expect(section.getByText('No apps are available.')).toHaveCount(0)
 await section.getByText('Workspace inventory',{exact:true}).click()
 const orphan = section.getByRole('table',{name:'Workspace keys in lp-app-orphan',exact:true})
 await expect(orphan.getByRole('cell',{name:'Unavailable',exact:true})).toHaveCount(2)
 await expect(orphan.getByText('No app declarations',{exact:true})).toHaveCount(0)
 state.failApps = false; state.apps = []
 await section.getByRole('button',{name:'Refresh secrets',exact:true}).click()
 await expect(section.getByText('No apps are available.')).toBeVisible()
 await expect(section.getByRole('alert')).toHaveCount(0)
})

test('the key editor fits desktop and narrow layouts',async ({page},testInfo) => {
 const {section} = await operatorFixture(page)
 await section.getByLabel('App name',{exact:true}).selectOption('provider')
 await section.getByLabel('Secret name',{exact:true}).selectOption(group)
 const live = section.getByRole('table',{name:`Keys in ${group}`,exact:true}).getByRole('row').filter({has:page.getByText('api-key',{exact:true})})
 await live.getByRole('button',{name:'Replace value',exact:true}).click()
 await page.setViewportSize({width:1440,height:1000})
 await section.screenshot({path:testInfo.outputPath('desktop.png')})
 await page.setViewportSize({width:390,height:844})
 await expect(section.getByLabel('Value',{exact:true})).toBeVisible()
 await section.getByRole('button',{name:'Save value',exact:true}).scrollIntoViewIfNeeded()
 await expect(section.getByRole('button',{name:'Save value',exact:true})).toBeInViewport()
 expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390)
 const field = await section.getByLabel('Value',{exact:true}).boundingBox()
 expect(field!.width).toBeGreaterThan(200)
 expect(field!.x + field!.width).toBeLessThanOrEqual(390)
 await section.screenshot({path:testInfo.outputPath('narrow.png')})
})

test('token renewal preserves selection and a late save cannot restore an obsolete editor',async ({page}) => {
 const {state,section} = await operatorFixture(page)
 await section.getByLabel('App name',{exact:true}).selectOption('provider')
 await section.getByLabel('Secret name',{exact:true}).selectOption(group)
 const live = section.getByRole('table',{name:`Keys in ${group}`,exact:true}).getByRole('row').filter({has:page.getByText('api-key',{exact:true})})
 await live.getByRole('button',{name:'Replace value',exact:true}).click()
 let release = () => {}
 state.reserveGate = new Promise<void>(resolve => {release = resolve})
 await section.getByLabel('Value',{exact:true}).fill('obsolete-edit')
 const reservation = page.waitForRequest(r => new URL(r.url()).pathname === '/v1/secrets/reserve')
 await section.getByRole('button',{name:'Save value',exact:true}).click()
 await reservation
 const refreshed = page.waitForResponse(r => new URL(r.url()).pathname === '/api/operator/apps' && r.request().headers().authorization?.endsWith('.renewed') === true)
 await page.evaluate(() => {
  const saved = JSON.parse(localStorage.getItem('sb-auth-auth-token')!)
  saved.access_token = saved.access_token.replace(/\.[^.]+$/,'.renewed')
  localStorage.setItem('sb-auth-auth-token',JSON.stringify(saved))
  new BroadcastChannel('sb-auth-auth-token').postMessage({event:'TOKEN_REFRESHED',session:saved})
 })
 await (await refreshed).finished()
 await expect(section.getByLabel('Secret name',{exact:true})).toHaveValue(group)
 await expect(live.getByRole('button',{name:'Replace value',exact:true})).toBeEnabled()
 await live.getByRole('button',{name:'Replace value',exact:true}).click()
 await section.getByLabel('Value',{exact:true}).fill('current-draft')
 const obsolete = page.waitForResponse(r => new URL(r.url()).pathname === '/v1/secrets/reserve')
 release(); await (await obsolete).finished()
 await expect(section.getByLabel('Value',{exact:true})).toHaveValue('current-draft')
 expect(state.mutations).toHaveLength(1)
})

for (const history of [false,true]) test(`refresh discards an Add editor for a ${history ? 'deleted' : 'shared unstored'} key whose declaration disappears`,async ({page}) => {
 const {state,section} = await operatorFixture(page)
 if (history) state.secrets.push({owner_id:vector.binding.owner_id,secret_id:'deleted-account',name:group,key:'account-id',version_id:'',revision:3,deleted:true})
 else state.apps[1].catalog_secrets.push(reference('account-id',group,'WORKER_ACCOUNT'))
 await section.getByRole('button',{name:'Refresh secrets',exact:true}).click()
 await section.getByLabel('App name',{exact:true}).selectOption('provider')
 await section.getByLabel('Secret name',{exact:true}).selectOption(group)
 const keys = section.getByRole('table',{name:`Keys in ${group}`,exact:true})
 const deleted = keys.getByRole('row').filter({has:page.getByText('account-id',{exact:true})})
 await deleted.getByRole('button',{name:'Add value',exact:true}).click()
 await section.getByLabel('Value',{exact:true}).fill('obsolete-declaration')
 state.apps[0].catalog_secrets = state.apps[0].catalog_secrets.filter(ref => ref.key !== 'account-id')
 await section.getByRole('button',{name:'Refresh secrets',exact:true}).click()
 await expect(section.getByText('Loading apps and secret entries…')).toBeHidden()
 await expect(section.getByLabel('Secret name',{exact:true})).toHaveValue(group)
 if (history) await expect(deleted).toContainText('Deleted')
 else await expect(deleted).toHaveCount(0)
 await expect(deleted.getByRole('button',{name:'Add value',exact:true})).toHaveCount(0)
 await expect(section.getByLabel('Value',{exact:true})).toHaveCount(0)
 expect(state.mutations).toHaveLength(0)
 state.apps[0].catalog_secrets.push(reference('account-id',group,'ACCOUNT_ID'))
 await section.getByRole('button',{name:'Refresh secrets',exact:true}).click()
 await expect(section.getByText('Loading apps and secret entries…')).toBeHidden()
 await expect(section.getByLabel('Value',{exact:true})).toHaveCount(0)
 await deleted.getByRole('button',{name:'Add value',exact:true}).click()
 await expect(section.getByLabel('Value',{exact:true})).toHaveValue('')
})
