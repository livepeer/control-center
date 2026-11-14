import type { Page } from '@playwright/test'
import { createHash, generateKeyPairSync, sign } from 'node:crypto'

export const secretsURL = 'https://controlcenter-secrets.livepeer.live'
const setupToken = 'setup.grant.signature'
const hash = (value: string) => createHash('sha256').update(value).digest('hex')
const canonical = (value: unknown) => JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)

export function enrollmentToken(control: string, setup = setupToken) {
  return 'lpcc1.' + Buffer.from(JSON.stringify({ version: 1, control, setup })).toString('base64url')
}

export async function mockSecrets(page: Page) {
  const identity = generateKeyPairSync('ed25519')
  const service = { origin: secretsURL, public_key: identity.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64') }
  await page.route('**/api/operator/apps?**', route => route.fulfill({ json: { apps: [] } }))
  await page.route(`${secretsURL}/**`, route => {
    const req = route.request(), url = new URL(req.url())
    const headers = { 'Access-Control-Allow-Origin': 'http://localhost:5173', 'Access-Control-Allow-Headers': 'authorization,content-type', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Expose-Headers': 'X-Livepeer-Service-Signature' }
    if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers })
    const body = url.pathname === '/v1/enrollment-grants' ? { token: setupToken, expires_at: new Date(Date.now() + 3600000).toISOString(), service } : { secrets: [] }
    const raw = JSON.stringify(body), digest = hash(canonical([req.method(), url.pathname + url.search, hash(req.postData() || '')]))
    const proof = JSON.stringify(['lpcc-secrets-response-v1', secretsURL, digest, hash(req.headers().authorization || ''), 200, hash(raw)])
    return route.fulfill({ body: raw, contentType: 'application/json', headers: { ...headers, 'X-Livepeer-Service-Signature': sign(null, Buffer.from(proof), identity.privateKey).toString('base64') } })
  })
}
