import {test,expect} from '@playwright/test'
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
   case '/api/config':return route.fulfill({json:{supabase_url:'http://auth.test',supabase_publishable_key:'fixture',public_api_url:'https://api.example',secrets_url:origin}})
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
 await page.getByLabel('Secret name').fill(secret.name);await page.getByLabel('Key',{exact:true}).fill(secret.key)
 const save=async()=>{await page.getByLabel('Value',{exact:true}).fill('plaintext-sentinel');await page.getByRole('button',{name:'Save secret'}).click()}
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
 expect(Buffer.from(plain).toString()).toBe('plaintext-sentinel');await expect(page.getByLabel('Value',{exact:true})).toHaveValue('')
 replacePin=true
 await page.getByRole('button',{name:'Refresh token'}).click()
 await expect(page.getByRole('alert')).toContainText('could not be authenticated')
 expect(await page.evaluate(origin=>JSON.parse(localStorage.getItem(`lpcc-secrets-service:${origin}`)!).public_key,vector.origin)).toBe(trust.public_key)
})
