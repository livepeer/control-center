import {test,expect} from '@playwright/test'
import {webcrypto} from 'node:crypto'

test('operator secret upload encrypts before leaving the client and enrollment grants stay separate', async({page})=>{
 const owner='11111111-1111-4111-8111-111111111111', expiry=Math.floor(Date.now()/1000)+3600
 const session={access_token:`e30.${Buffer.from(JSON.stringify({exp:expiry})).toString('base64url')}.fixture`,refresh_token:'fixture',token_type:'bearer',expires_at:expiry,expires_in:3600,user:{id:owner,email:'owner@example.invalid',aud:'authenticated',role:'authenticated',app_metadata:{},user_metadata:{},created_at:'2026-11-06T00:00:00Z'}}
 await page.addInitScript(s=>localStorage.setItem('sb-auth-auth-token',JSON.stringify(s)),session)
 await page.route('http://auth.test/**',r=>r.fulfill({json:session.user,headers:{'Access-Control-Allow-Origin':'*'}}))
 const secret={owner_id:owner,secret_id:'22222222-2222-4222-8222-222222222222',name:'lp-app-provider',key:'token',version_id:'33333333-3333-4333-8333-333333333333',revision:1,deleted:false}
 const mainRequests:string[]=[];let denied=false;let reserved=false;let failWrap=true;let dek:Buffer|undefined;let encrypted:Record<string,string>|undefined
 await page.route('**/api/**',route=>{const req=route.request();mainRequests.push(req.postData()||'');switch(new URL(req.url()).pathname){case '/api/config':return route.fulfill({json:{supabase_url:'http://auth.test',supabase_publishable_key:'fixture',public_api_url:'https://api.example',secrets_url:'https://secrets.test'}});case '/api/bootstrap-token':return route.fulfill({json:{token:'control.grant.signature',expires_at:new Date(expiry*1000).toISOString()}});case '/api/machines':return route.fulfill({json:{machines:[]}});case '/api/me':return route.fulfill({json:{user_id:owner,is_admin:false}});case '/api/operator/apps':return route.fulfill({json:{apps:[{name:'provider',aliases:[{name:'provider-alias'}],secrets:[{name:'API_TOKEN',secret:secret.name,key:secret.key}],machines:['owner-machine'],denied,generation:denied?1:0}]}});case '/api/operator/apps/provider/policy':denied=req.postDataJSON().denied;return route.fulfill({json:{generation:1}});default:return route.fulfill({status:404,json:{error:'unexpected'}})}})
 await page.route('https://secrets.test/**',route=>{const req=route.request(),path=new URL(req.url()).pathname;const headers={'Access-Control-Allow-Origin':'http://localhost:5173','Access-Control-Allow-Headers':'authorization,content-type','Access-Control-Allow-Methods':'GET,POST,PUT,OPTIONS'}
 if(req.method()==='OPTIONS')return route.fulfill({status:204,headers})
 if(path==='/v1/enrollment-grants')return route.fulfill({headers,json:{token:'setup.grant.signature',expires_at:new Date(expiry*1000).toISOString()}})
 if(path==='/v1/secrets')return route.fulfill({headers,json:{secrets:reserved?[secret]:[]}})
 if(path==='/v1/secrets/reserve'){expect(req.postDataJSON().expected_revision).toBe(reserved?1:0);reserved=true;return route.fulfill({headers,json:secret})}
 if(path.endsWith('/wrap')){if(failWrap){failWrap=false;return route.fulfill({status:503,headers,json:{code:'key_unavailable'}})}dek=Buffer.from(req.postDataJSON().data_key,'base64');return route.fulfill({headers,json:{wrapped_key:'vault:v1:fixture'}})}
 if(req.method()==='PUT'){encrypted=req.postDataJSON();return route.fulfill({headers,json:{revision:2}})}
 return route.fulfill({status:404,headers,json:{error:'unexpected'}})
 })
 await page.goto('/')
 await expect(page.getByRole('cell',{name:'provider-alias',exact:true})).toBeVisible()
 await page.getByRole('button',{name:'Deny',exact:true}).click()
 await expect(page.getByRole('button',{name:'Allow',exact:true})).toBeVisible()
 const command=page.getByLabel('Bootstrap command');await expect(command).toContainText('lpcc1.')
 const envelope=(await command.innerText()).match(/lpcc1\.([A-Za-z0-9_-]+)/)![1]
 expect(JSON.parse(Buffer.from(envelope,'base64url').toString())).toEqual({version:1,control:'control.grant.signature',setup:'setup.grant.signature'})
 await page.getByLabel('Secret name').fill(secret.name);await page.getByLabel('Key',{exact:true}).fill(secret.key);await page.getByLabel('Value',{exact:true}).fill('plaintext-sentinel');await page.getByRole('button',{name:'Save secret'}).click()
 await expect(page.getByRole('alert')).toContainText('key unavailable')
 await page.getByLabel('Value',{exact:true}).fill('plaintext-sentinel');await page.getByRole('button',{name:'Save secret'}).click()
 await expect(page.getByRole('status')).toContainText('Saved.')
 expect(mainRequests.join(' ')).not.toContain('plaintext-sentinel');expect(mainRequests.join(' ')).not.toContain('setup.grant.signature')
 expect(encrypted).toBeDefined();expect(dek).toBeDefined();expect(JSON.stringify(encrypted)).not.toContain('plaintext-sentinel')
 const key=await webcrypto.subtle.importKey('raw',dek!,'AES-GCM',false,['decrypt'])
 const aad=Buffer.from(JSON.stringify([1,owner,secret.secret_id,secret.name,secret.key,secret.version_id]))
 const plain=await webcrypto.subtle.decrypt({name:'AES-GCM',iv:Buffer.from(encrypted!.nonce,'base64'),additionalData:aad},key,Buffer.from(encrypted!.ciphertext,'base64'))
 expect(Buffer.from(plain).toString()).toBe('plaintext-sentinel');await expect(page.getByLabel('Value',{exact:true})).toHaveValue('')
})
