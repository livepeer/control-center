import assert from 'node:assert/strict'
import { test } from 'node:test'
import worker from './index.ts'
import type { Env } from './index.ts'

const loader = '#!/bin/sh\necho loader\n'
const objects = new Map<string, string>([
  ['bootstrap.sh', loader],
  ['releases/release-a/bootstrap.sh', '#!/bin/sh\necho release\n'],
  ['releases/release-a/runtime-bootstrap.tar.gz', 'bundle-bytes'],
  ['releases/release-a/SHA256SUMS', 'abc  runtime-bootstrap.tar.gz\n'],
  ['releases/release-a/release.json', '{"release_id":"release-a"}\n'],
  ['releases/release-a/notes.txt', 'unpublished'],
])

function bucket(failing = false): Env['BOOTSTRAP'] {
  const describe = (key: string) => {
    if (failing) throw new Error('R2 unavailable')
    const value = objects.get(key)
    return value === undefined ? null : { size: new TextEncoder().encode(value).length, httpEtag: `"${key.length}"`, value }
  }
  return {
    async head(key) { const found = describe(key); return found && { size: found.size, httpEtag: found.httpEtag } },
    async get(key) { const found = describe(key); return found && { size: found.size, httpEtag: found.httpEtag, body: new Response(found.value).body! } },
  }
}

async function call(path: string, init: RequestInit = {}, env: Env = { BOOTSTRAP: bucket() }) {
  return worker.fetch(new Request('https://controlcenter.example' + path, init), env)
}

test('serves the active loader as a shell script that is always revalidated', async () => {
  const response = await call('/bootstrap.sh')
  assert.equal(response.status, 200)
  assert.equal(response.headers.get('Content-Type'), 'text/x-shellscript')
  assert.equal(response.headers.get('Cache-Control'), 'no-cache')
  assert.equal(response.headers.get('X-Content-Type-Options'), 'nosniff')
  assert.equal(await response.text(), loader)
})

test('serves immutable release files with explicit content types', async () => {
  for (const [file, type] of [['runtime-bootstrap.tar.gz', 'application/gzip'], ['bootstrap.sh', 'text/x-shellscript'], ['SHA256SUMS', 'text/plain; charset=utf-8'], ['release.json', 'application/json']]) {
    const response = await call(`/bootstrap/releases/release-a/${file}`)
    assert.equal(response.status, 200, file)
    assert.equal(response.headers.get('Content-Type'), type, file)
    assert.equal(response.headers.get('Cache-Control'), 'public, max-age=31536000, immutable', file)
    assert.equal(await response.text(), objects.get(`releases/release-a/${file}`), file)
  }
})

test('HEAD returns headers without a body', async () => {
  const response = await call('/bootstrap/releases/release-a/runtime-bootstrap.tar.gz', { method: 'HEAD' })
  assert.equal(response.status, 200)
  assert.equal(response.headers.get('Content-Length'), String('bundle-bytes'.length))
  assert.equal(await response.text(), '')
})

test('missing or unsupported bootstrap paths are plain-text 404s, never HTML', async () => {
  for (const path of ['/bootstrap', '/bootstrap/', '/bootstrap/releases/', '/bootstrap/releases/missing/bootstrap.sh', '/bootstrap/releases/release-a/notes.txt', '/bootstrap/releases/release-a/', '/bootstrap/releases/../bootstrap.sh', '/bootstrap/releases/.hidden/bootstrap.sh', '/bootstrap/releases/a..b/bootstrap.sh', '/bootstrap/releases/release-a/nested/bootstrap.sh', '/bootstrap.sh/']) {
    const response = await call(path)
    assert.equal(response.status, 404, path)
    assert.equal(response.headers.get('Content-Type'), 'text/plain; charset=utf-8', path)
    assert.equal(response.headers.get('Cache-Control'), 'no-store', path)
    assert.doesNotMatch(await response.text(), /<html/i, path)
  }
})

test('rejects writes', async () => {
  const response = await call('/bootstrap.sh', { method: 'POST', body: 'x' })
  assert.equal(response.status, 405)
  assert.equal(response.headers.get('Allow'), 'GET, HEAD')
})

test('storage failures are retryable and never fall back to HTML', async () => {
  const response = await call('/bootstrap.sh', {}, { BOOTSTRAP: bucket(true) })
  assert.equal(response.status, 503)
  assert.equal(response.headers.get('Content-Type'), 'text/plain; charset=utf-8')
})

test('stale same-origin API calls get a JSON error instead of the SPA', async () => {
  for (const path of ['/api/config', '/api', '/api/machines?orchestrator_address=0x1']) {
    const response = await call(path)
    assert.equal(response.status, 404, path)
    assert.equal(response.headers.get('Content-Type'), 'application/json', path)
    assert.match((await response.json() as { error: string }).error, /Reload/, path)
  }
})
