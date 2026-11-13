import { Aes256Gcm, CipherSuite, HkdfSha256 } from '@hpke/core'
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519'

export type ServiceTrust = { origin: string; public_key: string }
export type Binding = { owner_id: string; secret_id: string; name: string; key: string; version_id: string }
const utf8 = new TextEncoder()
export const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b))
const unb64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0))
const digest = async (bytes: Uint8Array<ArrayBuffer>) =>
 Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('')
const canonical = (value: unknown) => JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
const pinName = (origin: string) => `lpcc-secrets-service:${origin}`
export function servicePin(origin: string): ServiceTrust | undefined {
 const raw = localStorage.getItem(pinName(origin))
 return raw ? JSON.parse(raw) as ServiceTrust : undefined
}
export function saveServicePin(trust: ServiceTrust) {
 const previous = servicePin(trust.origin)
 if (previous && previous.public_key !== trust.public_key) throw new Error('The secrets service identity changed. Restore the trusted key before continuing.')
 localStorage.setItem(pinName(trust.origin), JSON.stringify(trust))
 window.dispatchEvent(new Event('lpcc-secrets-enrolled'))
}

// Enrollment alone may establish the signing root. Later responses, including
// encryption-key discovery, must verify against that root and this exact request.
export async function verifyServiceResponse(trust: ServiceTrust, url: URL, method: string, authorization: string, request: string, response: Response, body: string) {
 if (trust.origin !== url.origin) throw new Error('Untrusted secrets service origin.')
 const target = url.pathname + url.search
 const requestHash = await digest(utf8.encode(canonical([method, target, await digest(utf8.encode(request))])))
 const proof = JSON.stringify(['lpcc-secrets-response-v1', trust.origin, requestHash, await digest(utf8.encode(authorization)), response.status, await digest(utf8.encode(body))])
 const signature = response.headers.get('X-Livepeer-Service-Signature')
 const key = await crypto.subtle.importKey('raw', unb64(trust.public_key), 'Ed25519', false, ['verify'])
 if (!signature || !await crypto.subtle.verify('Ed25519', key, unb64(signature), utf8.encode(proof))) {
  throw new Error('The secrets service response could not be authenticated.')
 }
}

export async function sealUploadKey(origin: string, binding: Binding, publicKey: string, dataKey: Uint8Array) {
 const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() })
 const recipientPublicKey = await suite.kem.deserializePublicKey(unb64(publicKey))
 const info = utf8.encode(JSON.stringify(['lpcc-data-key-v1', 'upload', origin, binding.owner_id, binding.secret_id, binding.name, binding.key, binding.version_id]))
 const sealed = await suite.seal({ recipientPublicKey, info }, dataKey)
 const bytes = new Uint8Array(new Uint8Array(sealed.enc).length + new Uint8Array(sealed.ct).length)
 bytes.set(new Uint8Array(sealed.enc))
 bytes.set(new Uint8Array(sealed.ct), new Uint8Array(sealed.enc).length)
 return b64(bytes)
}
