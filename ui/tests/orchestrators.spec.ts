import { test, expect } from '@playwright/test'
import type { Page, Route } from '@playwright/test'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { readFile } from 'node:fs/promises'

const a = '0x1111111111111111111111111111111111111111'
const b = '0x2222222222222222222222222222222222222222'
const user = '11111111-1111-4111-8111-111111111111'
const otherUser = '22222222-2222-4222-8222-222222222222'
const groups = [{ address: b, display_name: 'Beta' }, { address: a, display_name: 'Alpha' }]
const canonical = (v: unknown) => JSON.stringify(v).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4,'0')}`)
const hash = (s: string) => createHash('sha256').update(s).digest('hex')
function session(id = user) {
  const exp = Math.floor(Date.now()/1000)+3600
  return { access_token: `e30.${Buffer.from(JSON.stringify({sub:id,exp})).toString('base64url')}.fixture`, refresh_token:'fixture',token_type:'bearer',expires_at:exp,expires_in:3600,user:{id,email:`${id}@example.invalid`,aud:'authenticated',role:'authenticated',app_metadata:{},user_metadata:{},created_at:'2026-11-06T00:00:00Z'} }
}
function machine(address: string) { return { node_id:address,hostname:address===a?'alpha-machine':'beta-machine',created_at:'2026-11-06T00:00:00Z',last_config_fetch_at:null } }

async function setup(page: Page, { secrets = false, empty = false, admin = false, hold = false, setupFailure = 0, mode = 'offchain', inactive = false } = {}) {
  const state = { setupFailure, controlGrants:0, membershipTokens:[] as string[], holdPolicy:false, heldPolicy:null as Route|null, groups:empty?[]:groups, fail:false, denied:new Set<string>(),hold,held:[] as Route[],reserve:null as Route|null,completeReserve:null as (()=>Promise<void>)|null,holdReserve:false,wraps:[] as string[],policies:[] as string[], challengeRequests:0, claims:[] as Record<string,string>[] }
  await page.addInitScript(saved => {
    localStorage.setItem('sb-auth-auth-token',JSON.stringify(saved))
    // Exercise responses that have already escaped transport cancellation.
    const original=window.fetch.bind(window)
    window.fetch=(input,options)=>original(input,{...options,signal:undefined})
  },session())
  await page.route('http://auth.test/**',route=>route.fulfill({json:session().user,headers:{'Access-Control-Allow-Origin':'*'}}))
  await page.route('**/api/**',route=>{
    const req=route.request(),url=new URL(req.url()),path=url.pathname,address=url.searchParams.get('orchestrator_address')??''
    if(path==='/api/config')return route.fulfill({json:{supabase_url:'http://auth.test',supabase_publishable_key:'fixture'}})
    if(path==='/api/orchestrators/challenge') {state.challengeRequests++;return route.fulfill(inactive?{status:403,json:{error:'Orchestrator is not active on chain.'}}:{json:{challenge:'header.payload.signature',expires_at:new Date(Date.now()+3600000).toISOString()}})}
    if(path==='/api/orchestrators'&&req.method()==='POST') {const body=req.postDataJSON() as Record<string,string>;state.claims.push(body);const claimed=(body.address||'0x0000000000000000000000000000000000000000').toLowerCase();state.groups=[...state.groups,{address:claimed,display_name:''}];return route.fulfill({status:201,json:{address:claimed}})}
    if(path==='/api/orchestrators'){state.membershipTokens.push(req.headers().authorization);return route.fulfill(state.fail?{status:503,json:{error:'Membership service unavailable.'}}:{json:{orchestrators:state.groups}})}
    if(path==='/api/operator/config')return route.fulfill({json:{public_api_url:'https://api.example',mode,...(secrets?{secrets_url:'https://secrets.test'}:{})}})
    if(path==='/api/me')return route.fulfill({json:{user_id:req.headers().authorization===`Bearer ${session(otherUser).access_token}`?otherUser:user,is_admin:admin}})
    if(path.startsWith('/api/admin/'))return route.fulfill({json:{administrators:[],machines:[],apps:[]}})
    if(path==='/api/bootstrap-token'){
      state.controlGrants++
      const target=req.postDataJSON()?.orchestrator_address
      if(state.hold&&target===a){state.held.push(route);return}
      return route.fulfill({json:{token:`control-${target}`,expires_at:new Date(Date.now()+3600000).toISOString()}})
    }
    if(path==='/api/machines'){
      if(state.denied.has(address))return route.fulfill({status:403,json:{error:'Orchestrator access is required.'}})
      if(state.hold&&address===a){state.held.push(route);return}
      return route.fulfill({json:{machines:[machine(address)]}})
    }
    if(path==='/api/operator/apps')return route.fulfill({json:{apps:[{name:'provider',denied:false,generation:0,secrets:[{name:'API_TOKEN',secret:'lp-app-provider',key:'token'}]}]}})
    if(path.endsWith('/policy')){state.policies.push(address);if(state.holdPolicy){state.heldPolicy=route;return};return route.fulfill({json:{generation:1}})}
    return route.fulfill({status:404,json:{error:'Unexpected route'}})
  })
  if(secrets){
    const identity=generateKeyPairSync('ed25519'),encryption=generateKeyPairSync('x25519')
    const service={origin:'https://secrets.test',public_key:identity.publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('base64')}
    await page.route('https://secrets.test/**',route=>{
      const req=route.request(),url=new URL(req.url()),address=url.searchParams.get('orchestrator_address')!
      const headers={'Access-Control-Allow-Origin':'http://localhost:5173','Access-Control-Allow-Headers':'authorization,content-type','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS','Access-Control-Expose-Headers':'X-Livepeer-Service-Signature'}
      if(req.method()==='OPTIONS')return route.fulfill({status:204,headers})
      const reply=(body:unknown,status=200)=>{
        const raw=JSON.stringify(body),digest=hash(canonical([req.method(),url.pathname+url.search,hash(req.postData()||'')]))
        const proof=JSON.stringify(['lpcc-secrets-response-v1',service.origin,digest,hash(req.headers().authorization||''),status,hash(raw)])
        return route.fulfill({status,body:raw,contentType:'application/json',headers:{...headers,'X-Livepeer-Service-Signature':sign(null,Buffer.from(proof),identity.privateKey).toString('base64')}})
      }
      if(url.pathname==='/v1/enrollment-grants'&&state.setupFailure)return reply({code:state.setupFailure===403?'orchestrator_access_required':'authentication_required'},state.setupFailure)
      if(url.pathname==='/v1/enrollment-grants')return reply({token:`setup-${address}`,expires_at:new Date(Date.now()+3600000).toISOString(),service})
      if(url.pathname==='/v1/secrets')return reply({secrets:[]})
      if(url.pathname==='/v1/secrets/reserve'&&state.holdReserve){state.reserve=route;state.completeReserve=()=>reply({orchestrator_address:address,secret_id:'reserved-old-scope',name:'lp-app-provider',key:'token',version_id:'old-version',revision:1});return}
      state.wraps.push(url.pathname)
      if(url.pathname==='/v1/encryption-key')return reply({public_key:encryption.publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('base64')})
      if(url.pathname.endsWith('/wrap'))return reply({wrapped_key:'vault:v1:fixture'})
      return reply({revision:2})
    })
  }
  await page.goto('/')
  return state
}

test('switching scopes enrollment and inventory and ignores old responses',async({page})=>{
  const state=await setup(page,{hold:true})
  const selector=page.getByRole('combobox',{name:'Orchestrator'})
  await expect(selector).toHaveValue(a)
  await expect.poll(()=>state.held.length).toBe(2)
  await selector.selectOption(b)
  await expect(page.getByLabel('Bootstrap command')).toContainText(`control-${b}`)
  await expect(page.getByText('beta-machine',{exact:true})).toBeVisible()
  for(const route of state.held){
    const body=new URL(route.request().url()).pathname==='/api/machines'?{machines:[machine(a)]}:{token:'obsolete-alpha-command',expires_at:new Date(Date.now()+3600000).toISOString()}
    await route.fulfill({json:body})
  }
  await expect(page.getByText('alpha-machine',{exact:true})).toHaveCount(0)
  await expect(page.getByLabel('Bootstrap command')).not.toContainText('obsolete-alpha-command')
  state.hold=false
  await page.reload()
  await expect(selector).toHaveValue(b)
  await expect(page.getByLabel('Bootstrap command')).toContainText(`control-${b}`)
})

test('no membership hides scoped content while global Administration remains available',async({page})=>{
  const state=await setup(page,{empty:true,admin:true})
  await expect(page.getByText('No orchestrators are linked to your account.',{exact:false})).toBeVisible()
  await expect(page.getByLabel('Bootstrap command')).toHaveCount(0)
  await expect(page.getByRole('heading',{name:'Administration',exact:true})).toBeVisible()
  state.groups=groups
  await page.evaluate(()=>window.dispatchEvent(new Event('focus')))
  await expect(page.getByLabel('Bootstrap command')).toContainText(`control-${a}`)
})

test('onchain address check reveals signing instructions and claim selects enrollment',async({page})=>{
  const state=await setup(page,{empty:true,mode:'onchain'})
  await page.getByRole('button',{name:'Add orchestrator'}).click()
  await page.getByLabel('Orchestrator address').fill(a)
  await expect(page.getByLabel('Signing command')).toHaveCount(0)
  await page.getByRole('button',{name:'Check active address'}).click()
  await expect(page.getByLabel('Signing command')).toContainText('livepeer chain sign message --message-file ./orchestrator-claim.jwt')
  const download=page.waitForEvent('download')
  await page.getByRole('button',{name:'Download orchestrator-claim.jwt'}).click()
  const file=await download
  expect(file.suggestedFilename()).toBe('orchestrator-claim.jwt')
  expect(await readFile(await file.path(),'utf8')).toBe('header.payload.signature')
  await page.getByLabel('Signature').fill('0xsigned')
  await page.getByRole('button',{name:'Claim orchestrator'}).click()
  await expect(page.getByRole('combobox',{name:'Orchestrator'})).toHaveValue(a)
  await expect(page.getByLabel('Bootstrap command')).toContainText(`control-${a}`)
  expect(state.challengeRequests).toBe(1)
  expect(state.claims).toEqual([{address:a,challenge:'header.payload.signature',signature:'0xsigned'}])
})

test('offchain workspace defaults to the zero address',async({page})=>{
  const state=await setup(page,{empty:true})
  await page.getByRole('button',{name:'Add orchestrator'}).click()
  await page.getByRole('button',{name:'Add workspace'}).click()
  await expect(page.getByRole('combobox',{name:'Orchestrator'})).toHaveValue('0x0000000000000000000000000000000000000000')
  expect(state.claims).toEqual([{address:''}])
  expect(state.challengeRequests).toBe(0)
})

test('inactive address never reveals signing instructions',async({page})=>{
  await setup(page,{empty:true,mode:'onchain',inactive:true})
  await page.getByRole('button',{name:'Add orchestrator'}).click()
  await page.getByLabel('Orchestrator address').fill(a)
  await page.getByRole('button',{name:'Check active address'}).click()
  await expect(page.getByRole('alert')).toContainText('Orchestrator is not active on chain.')
  await expect(page.getByLabel('Signing command')).toHaveCount(0)
})

test('membership loss clears the old orchestrator and account selection stays separate',async({page})=>{
  const state=await setup(page)
  await expect(page.getByText('alpha-machine',{exact:true})).toBeVisible()
  state.denied.add(a);state.groups=[groups[0]]
  await page.evaluate(()=>document.dispatchEvent(new Event('visibilitychange')))
  await expect(page.getByRole('combobox',{name:'Orchestrator'})).toHaveValue(b)
  await expect(page.getByText('alpha-machine',{exact:true})).toHaveCount(0)
  state.groups=groups
  await page.evaluate(saved=>{
    localStorage.setItem('sb-auth-auth-token',JSON.stringify(saved))
    new BroadcastChannel('sb-auth-auth-token').postMessage({event:'SIGNED_IN',session:saved})
  },session(otherUser))
  state.denied.clear()
  await expect(page.locator('.account-email')).toHaveText(`${otherUser}@example.invalid`)
  await expect(page.getByRole('combobox',{name:'Orchestrator'})).toHaveValue(a)
})

test('switching clears secret drafts and stops a delayed upload from progressing',async({page})=>{
  const state=await setup(page,{secrets:true})
  await expect(page.getByLabel('Bootstrap command')).toContainText('lpcc1.')
  state.holdReserve=true
  await page.getByLabel('App name',{exact:true}).selectOption('provider')
  await page.getByLabel('Secret name',{exact:true}).selectOption('lp-app-provider')
  await page.getByRole('button',{name:'Add value',exact:true}).click()
  await page.getByLabel('Value',{exact:true}).fill('private-draft')
  await page.getByRole('button',{name:'Save value',exact:true}).click()
  await expect.poll(()=>state.reserve!==null).toBe(true)
  await page.getByRole('combobox',{name:'Orchestrator'}).selectOption(b)
  await expect(page.getByLabel('Secret name')).toHaveValue('')
  await expect(page.getByLabel('Value',{exact:true})).toHaveCount(0)
  await state.completeReserve!()
  await page.getByRole('button',{name:'Deny',exact:true}).click()
  await expect.poll(()=>state.policies).toEqual([b])
  expect(state.wraps).toEqual([])
})

for(const status of [401,403])test(`persistent secrets ${status} preserves its error without regenerating commands`,async({page})=>{
  const state=await setup(page,{secrets:true,setupFailure:status})
  await expect(page.getByRole('alert')).toContainText(status===403?'orchestrator access required':'authentication required')
  await expect.poll(()=>state.membershipTokens.length).toBe(2)
  await page.evaluate(()=>new Promise<void>(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve()))))
  expect(state.controlGrants).toBe(1)
  await expect(page.getByText('alpha-machine',{exact:true})).toBeVisible()
})

test('background membership outage preserves a draft and an in-flight secret save',async({page})=>{
  const state=await setup(page,{secrets:true})
  await expect(page.getByLabel('Bootstrap command')).toContainText('lpcc1.')
  const command=await page.getByLabel('Bootstrap command').innerText()
  state.holdReserve=true
  await page.getByLabel('App name',{exact:true}).selectOption('provider')
  await page.getByLabel('Secret name',{exact:true}).selectOption('lp-app-provider')
  await page.getByRole('button',{name:'Add value',exact:true}).click()
  await page.getByLabel('Value',{exact:true}).fill('retained-private-draft')
  await page.getByRole('button',{name:'Save value',exact:true}).click()
  await expect.poll(()=>state.reserve!==null).toBe(true)
  state.fail=true
  await page.evaluate(()=>window.dispatchEvent(new Event('focus')))
  await expect(page.getByRole('alert')).toContainText('Membership service unavailable.')
  await expect(page.getByLabel('Value',{exact:true})).toHaveValue('retained-private-draft')
  await expect(page.getByLabel('Bootstrap command')).toHaveText(command)
  await expect(page.getByRole('button',{name:'Saving…',exact:true})).toBeDisabled()
  state.fail=false
  await page.getByRole('button',{name:'Retry orchestrators'}).click()
  await expect(page.getByRole('alert')).toHaveCount(0)
  await state.completeReserve!()
  await expect(page.getByRole('status')).toContainText('Saved. Affected apps will rotate automatically')
  expect(state.wraps).toEqual(['/v1/encryption-key','/v1/secrets/reserved-old-scope/wrap','/v1/secrets/reserved-old-scope'])
})

test('a late old-token authorization failure refreshes memberships with the current session',async({page})=>{
  const state=await setup(page,{secrets:true})
  await expect(page.getByLabel('Bootstrap command')).toContainText('lpcc1.')
  state.holdPolicy=true
  await page.getByRole('button',{name:'Deny',exact:true}).click()
  await expect.poll(()=>state.heldPolicy!==null).toBe(true)
  const next={...session(),access_token:session().access_token.replace('.fixture','.renewed')}
  await page.evaluate(saved=>{
    localStorage.setItem('sb-auth-auth-token',JSON.stringify(saved))
    new BroadcastChannel('sb-auth-auth-token').postMessage({event:'TOKEN_REFRESHED',session:saved})
  },next)
  await expect.poll(()=>state.membershipTokens.at(-1)).toBe(`Bearer ${next.access_token}`)
  await expect.poll(()=>state.controlGrants).toBe(2)
  state.membershipTokens=[]
  await state.heldPolicy!.fulfill({status:403,json:{error:'Old policy request refused.',code:'orchestrator_access_required'}})
  await expect.poll(()=>state.membershipTokens.length).toBeGreaterThan(0)
  expect(state.membershipTokens.every(token=>token===`Bearer ${next.access_token}`)).toBe(true)
  await expect(page.getByRole('combobox',{name:'Orchestrator'})).toHaveValue(a)
  expect(state.controlGrants).toBe(2)
})
