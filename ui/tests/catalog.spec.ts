import { mockSecrets, secretsURL } from './secrets-fixture'
import { test, expect } from '@playwright/test'
import type { Page, Route } from '@playwright/test'

const id = '11111111-1111-4111-8111-111111111111'
const revisionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const exp = Math.floor(Date.now() / 1000) + 3600
function session(token = 'first', actor = id) {
  return { access_token: `${Buffer.from('{}').toString('base64url')}.${Buffer.from(JSON.stringify({ sub: actor, exp })).toString('base64url')}.${token}`, refresh_token: 'fixture', token_type: 'bearer', expires_at: exp, expires_in: 3600, user: { id: actor, email: actor === id ? 'a@example.invalid' : 'b@example.invalid', aud: 'authenticated', role: 'authenticated', app_metadata: {}, user_metadata: {}, created_at: '2026-11-06T00:00:00Z' } }
}
async function authenticate(page: Page, saved: ReturnType<typeof session>, event = 'TOKEN_REFRESHED') {
  await page.evaluate(({ saved, event }) => { localStorage.setItem('sb-auth-auth-token', JSON.stringify(saved)); new BroadcastChannel('sb-auth-auth-token').postMessage({ event, session: saved }) }, { saved, event })
}
async function setup(page: Page, existing = false, paginated = false) {
  const state = { admin: true, hold: false, held: null as Route | null, reject: 0, published: null as unknown, conflict: false, head: revisionId, holdCapability: '' as '' | 'me' | 'fleet', heldCapability: null as Route | null, capabilityRequests: 0, createdName: 'example', holdHistory: false, heldHistory: null as Route | null, holdMutation: false, heldMutations: [] as Route[] }
  const revision = { revision_id: revisionId, name: 'example', source_toml: 'name="example"', definition: { name: 'example' }, digest: 'sha256:published', revision: paginated ? 2 : 1, lifecycle: { version: 1, retired_at: null }, published_at: '2026-11-06T00:00:00Z', published_by: id }
  await page.addInitScript(saved => {
    localStorage.setItem('sb-auth-auth-token', JSON.stringify(saved))
    const original = window.fetch.bind(window)
    window.fetch = (input, options) => original(input, String(input).startsWith('/api/') ? { ...options, signal: undefined } : options)
  }, session())
  await page.route('http://auth.test/**', route => route.fulfill({ json: session().user, headers: { 'Access-Control-Allow-Origin': '*' } }))
  await page.route('**/api/**', async route => {
    const p = new URL(route.request().url()).pathname
    if (p === '/api/orchestrators') return route.fulfill({ json: { orchestrators: [{ address: '0x1111111111111111111111111111111111111111', display_name: 'Test orchestrator' }] } })
    if (p === '/api/config') return route.fulfill({ json: { supabase_url: 'http://auth.test', supabase_publishable_key: 'fixture-public' } })
    if (p === '/api/operator/config') return route.fulfill({ json: { public_api_url: 'http://localhost:41932', secrets_url: secretsURL } })
    if (p === '/api/bootstrap-token') return route.fulfill({ json: { token: 'fixture', expires_at: new Date(Date.now() + 3600000).toISOString() } })
    if (p === '/api/me') {
      state.capabilityRequests++
      if (state.holdCapability === 'me') { state.heldCapability = route; return }
      const actor = route.request().headers().authorization?.includes(session().access_token.split('.')[1]) ? id : '22222222-2222-4222-8222-222222222222'
      return route.fulfill({ json: { user_id: actor, is_admin: state.admin && actor === id } })
    }
    if (p === '/api/admin/administrators') return route.fulfill({ json: { administrators: [] } })
    if (p === '/api/admin/machines' && state.holdCapability === 'fleet') { state.heldCapability = route; return }
    if (p.endsWith('/machines')) return route.fulfill({ json: { machines: [] } })
    if (p === '/api/admin/apps/validate') {
      if (state.hold) { state.held = route; return }
      if (state.reject) return route.fulfill({ status: state.reject, json: { error: 'Fix definition', code: 'invalid_definition', fields: [{ path: 'price.amount', code: 'invalid_field', message: 'Positive price required.' }] } })
      return route.fulfill({ json: { definition: { name: 'example' }, digest: 'sha256:validated', payment_mode: 'offchain' } })
    }
    if (state.holdMutation && route.request().method() === 'POST' && (p === '/api/admin/apps' || p.endsWith('/revisions') || p.endsWith('/retire'))) { state.heldMutations.push(route); return }
    if (p.endsWith('/retire')) return route.fulfill({ json: { changed: true, revision: { ...revision, lifecycle: { version: 2, retired_at: '2026-11-06T01:00:00Z' } } } })
    if (p === '/api/admin/apps/example/revisions' && route.request().method() === 'POST') {
      state.published = route.request().postDataJSON()
      if (state.conflict) return route.fulfill({ status: 409, json: { error: 'Refresh before publishing.', code: 'stale_head' } })
      return route.fulfill({ status: 201, json: { changed: true, revision } })
    }
    if (p === '/api/admin/apps' && route.request().method() === 'POST') {
      state.published = route.request().postDataJSON()
      return route.fulfill({ status: 201, json: { changed: true, revision: { ...revision, revision_id: state.head, name: state.createdName, source_toml: `name="${state.createdName}"` } } })
    }
    if (p === '/api/admin/apps') return route.fulfill({ json: { apps: existing ? [{ name: 'example', head: revision, revision_count: 1, active_revision_count: 1 }] : [], payment_mode: 'offchain', next_after_name: null } })
    if (p === '/api/admin/apps/example' || p === `/api/admin/apps/${state.createdName}`) {
      if (state.holdHistory) { state.heldHistory = route; return }
      return route.fulfill({ json: { app: { name: p.split('/').at(-1), head: { revision_id: state.head } }, revisions: [], next_before_revision: paginated && !new URL(route.request().url()).searchParams.has('before_revision') ? revision.revision : null, payment_mode: 'offchain' } })
    }
    if (p === '/api/admin/apps/example/revisions/' + revisionId) return route.fulfill({ json: revision })
    return route.fulfill({ status: 404, json: { error: 'Unexpected route' } })
  })
  await mockSecrets(page)
  await page.goto('/')
  if (existing) {
    await page.getByRole('button', { name: 'example', exact: true }).click()
    await page.getByRole('button', { name: 'Publish new revision', exact: true }).click()
  } else await page.getByRole('button', { name: 'Create app', exact: true }).click()
  return Object.assign(state, { revision })
}

test('catalog draft survives capability refresh and same-account token renewal', async ({ page }) => {
  await setup(page)
  await page.getByLabel('New app TOML').fill('private draft')
  const checked = page.waitForResponse(r => r.url().endsWith('/api/me'))
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await (await checked).finished()
  await expect(page.getByLabel('New app TOML')).toHaveValue('private draft')
  await authenticate(page, session('renewed'))
  await expect(page.getByLabel('New app TOML')).toHaveValue('private draft')
})
for (const stage of ['me', 'fleet'] as const) {
  test(`renewal during pending ${stage} refresh resumes authority polling`, async ({ page }) => {
    const state = await setup(page)
    await page.getByLabel('New app TOML').fill('private draft')
    state.holdCapability = stage
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
    await expect.poll(() => !!state.heldCapability).toBe(true)
    const requests = state.capabilityRequests
    state.holdCapability = ''
    await authenticate(page, session('renewed'))
    await expect.poll(() => state.capabilityRequests).toBeGreaterThan(requests)
    await state.heldCapability!.fulfill(stage === 'me' ? { json: { user_id: id, is_admin: false } } : { status: 503, json: { error: 'Obsolete outage' } })
    await expect(page.getByLabel('New app TOML')).toHaveValue('private draft')
    state.admin = false
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
    await expect(page.getByLabel('New app TOML')).toHaveCount(0)
  })
}
test('stale validation cannot restore a preview after another edit', async ({ page }) => {
  const state = await setup(page); state.hold = true
  await page.getByRole('button', { name: 'Validate definition' }).click()
  await expect.poll(() => !!state.held).toBe(true)
  await page.getByLabel('New app TOML').fill('newer draft')
  await state.held!.fulfill({ json: { definition: {}, digest: 'obsolete-preview', payment_mode: 'offchain' } })
  await expect(page.getByRole('button', { name: 'Publish definition' })).toBeDisabled()
  await expect(page.getByText('obsolete-preview')).toHaveCount(0)
})
test('field errors render and a validated draft publishes immutable content', async ({ page }) => {
  const state = await setup(page); state.reject = 400
  await page.getByRole('button', { name: 'Validate definition' }).click()
  await expect(page.getByRole('alert')).toContainText('price.amount')
  state.reject = 0
  await page.getByRole('button', { name: 'Validate definition' }).click()
  await expect(page.getByRole('button', { name: 'Publish definition' })).toBeEnabled()
  await page.getByRole('button', { name: 'Publish definition' }).click()
  await expect(page.getByRole('status')).toContainText('Revision published.')
  expect(state.published).toHaveProperty('source_toml')
})
test('lost authority clears the draft and late validation data', async ({ page }) => {
  const state = await setup(page); state.hold = true
  await page.getByLabel('New app TOML').fill('privileged draft')
  await page.getByRole('button', { name: 'Validate definition' }).click()
  await expect.poll(() => !!state.held).toBe(true)
  state.admin = false
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(page.getByLabel('New app TOML')).toHaveCount(0)
  await state.held!.fulfill({ json: { definition: {}, digest: 'obsolete-private', payment_mode: 'offchain' } })
  await expect(page.getByText('obsolete-private')).toHaveCount(0)
  state.admin = true
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await page.getByRole('button', { name: 'Create app', exact: true }).click()
  await expect(page.getByLabel('New app TOML')).not.toHaveValue('privileged draft')
})

test('stale head preserves the draft and explicitly refreshes the publication base', async ({ page }) => {
  const state = await setup(page, true)
  await page.getByLabel('New revision TOML').fill('name="example" # edited draft')
  await page.getByRole('button', { name: 'Validate definition' }).click()
  await expect(page.getByRole('button', { name: 'Publish definition' })).toBeEnabled()
  state.conflict = true
  await page.getByRole('button', { name: 'Publish definition' }).click()
  await expect(page.getByLabel('New revision TOML')).toHaveValue('name="example" # edited draft')
  state.head = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
  await page.getByRole('button', { name: 'Refresh publication base' }).click()
  await expect(page.getByRole('status')).toContainText('Publication base refreshed')
  state.reject = 400
  await page.getByRole('button', { name: 'Validate definition' }).click()
  await expect(page.getByRole('alert')).toContainText('price.amount')
  await expect(page.getByRole('status')).toHaveCount(0)
  state.reject = 0
  await page.getByRole('button', { name: 'Validate definition' }).click()
  await expect(page.getByRole('button', { name: 'Publish definition' })).toBeEnabled()
  state.conflict = false
  await page.getByRole('button', { name: 'Publish definition' }).click()
  await expect(page.getByRole('status')).toContainText('Revision published')
  expect(state.published).toHaveProperty('expected_head_revision_id', state.head)
})

test('history pagination preserves a validated draft publication base', async ({ page }) => {
  const state = await setup(page, true, true)
  await page.getByLabel('New revision TOML').fill('name="example" # based on A')
  await page.getByRole('button', { name: 'Validate definition' }).click()
  await expect(page.getByRole('button', { name: 'Publish definition' })).toBeEnabled()
  state.head = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
  await page.getByRole('button', { name: 'Older revisions' }).click()
  await expect(page.getByRole('button', { name: 'Older revisions' })).toHaveCount(0)
  state.conflict = true
  await page.getByRole('button', { name: 'Publish definition' }).click()
  await expect(page.getByRole('button', { name: 'Refresh publication base' })).toBeVisible()
  expect(state.published).toHaveProperty('expected_head_revision_id', revisionId)
  await expect(page.getByLabel('New revision TOML')).toHaveValue('name="example" # based on A')
})

test('creating another app waits for its metadata before another edit', async ({ page }) => {
  const state = await setup(page, true)
  await page.getByRole('button', { name: 'Cancel edit' }).click()
  state.createdName = 'beta'; state.head = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
  await page.getByRole('button', { name: 'Create app', exact: true }).click()
  await page.getByLabel('New app TOML').fill('name="beta"')
  await page.getByRole('button', { name: 'Validate definition' }).click()
  await expect(page.getByRole('button', { name: 'Publish definition' })).toBeEnabled()
  state.holdHistory = true
  await page.getByRole('button', { name: 'Publish definition' }).click()
  await expect.poll(() => !!state.heldHistory).toBe(true)
  await expect(page.getByRole('button', { name: 'Publish new revision', exact: true })).toBeDisabled()
  await state.heldHistory!.fulfill({ json: { app: { name: 'beta', head: { revision_id: state.head } }, revisions: [], next_before_revision: null, payment_mode: 'offchain' } })
  await page.getByRole('button', { name: 'Publish new revision', exact: true }).click()
  await expect(page.getByLabel('New revision TOML')).toHaveValue('name="beta"')
})

test('account switch clears an edit and ignores its delayed validation', async ({ page }) => {
  const state = await setup(page); state.hold = true
  await page.getByLabel('New app TOML').fill('account A private draft')
  await page.getByRole('button', { name: 'Validate definition' }).click()
  await expect.poll(() => !!state.held).toBe(true)
  await authenticate(page, session('other-account', '22222222-2222-4222-8222-222222222222'), 'SIGNED_IN')
  await expect(page.getByLabel('New app TOML')).toHaveCount(0)
  await state.held!.fulfill({ json: { definition: {}, digest: 'obsolete-account-preview', payment_mode: 'offchain' } })
  await expect(page.getByText('obsolete-account-preview')).toHaveCount(0)
  await authenticate(page, session('returned'), 'SIGNED_IN')
  await page.getByRole('button', { name: 'Create app', exact: true }).click()
  await expect(page.getByLabel('New app TOML')).not.toHaveValue('account A private draft')
})

for (const action of ['publish', 'retire'] as const) {
  test(`late ${action} after renewal cannot replace state or finish a new mutation`, async ({ page }) => {
    const state = await setup(page, true)
    if (action === 'publish') {
      await page.getByLabel('New revision TOML').fill('name="example" # current draft')
      await page.getByRole('button', { name: 'Validate definition' }).click()
      await expect(page.getByRole('button', { name: 'Publish definition' })).toBeEnabled()
    } else await page.getByRole('button', { name: 'Cancel edit' }).click()
    const button = page.getByRole('button', { name: action === 'publish' ? 'Publish definition' : 'Retire revision', exact: true })
    state.holdMutation = true
    await button.click()
    await expect.poll(() => state.heldMutations.length).toBe(1)
    const renewed = session('renewed')
    const refreshed = page.waitForRequest(request => new URL(request.url()).pathname === '/api/admin/apps' && request.headers().authorization === 'Bearer ' + renewed.access_token)
    await authenticate(page, renewed)
    await refreshed
    await expect(button).toBeEnabled()
    await button.click()
    await expect.poll(() => state.heldMutations.length).toBe(2)
    const oldResponse = page.waitForResponse(response => response.request().headers().authorization === 'Bearer ' + session().access_token && response.request().method() === 'POST')
    await state.heldMutations[0].fulfill({ json: { changed: true, revision: { ...state.revision, digest: 'obsolete-mutation' } } })
    await (await oldResponse).finished()
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))))
    await expect(page.getByText('obsolete-mutation')).toHaveCount(0)
    await expect(button).toBeDisabled()
    if (action === 'publish') await expect(page.getByLabel('New revision TOML')).toHaveValue('name="example" # current draft')
    await state.heldMutations[1].fulfill({ json: { changed: true, revision: { ...state.revision, digest: 'current-mutation', lifecycle: action === 'retire' ? { version: 2, retired_at: '2026-11-06T01:00:00Z' } : state.revision.lifecycle } } })
    await expect(page.getByText('current-mutation')).toBeVisible()
  })
}
