import { mockSecrets, secretsURL } from './secrets-fixture'
import { test, expect } from '@playwright/test'
import type { Page, Route } from '@playwright/test'

const owner = '11111111-1111-4111-8111-111111111111'
const r1 = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', r2 = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const node = 'vkvkvkvkvkvkuaaaaaaaaaaaaa', base = `/api/admin/machines/${node}/apps`
const expires = Math.floor(Date.now() / 1000) + 3600
const saved = { access_token: `${Buffer.from('{}').toString('base64url')}.${Buffer.from(JSON.stringify({ sub: owner, exp: expires })).toString('base64url')}.fixture`, refresh_token: 'fixture', token_type: 'bearer', expires_at: expires, expires_in: 3600, user: { id: owner, email: 'a@example.invalid', aud: 'authenticated', role: 'authenticated', app_metadata: {}, user_metadata: {}, created_at: '2026-11-07T00:00:00Z' } }
function revision(id: string, n: number) { return { revision_id: id, digest: 'sha256:' + (n === 1 ? 'a' : 'b').repeat(64), name: 'whoami', revision: n, app_version: String(n), lifecycle: { retired_at: null, version: 1 }, definition: { name: 'whoami', instances: { replicas: 2 } } } }
type Assignment = { revision_id: string; digest: string; app_name: string; revision_number: number; generation: number; activation_generation: number; desired: string; replicas?: number; revision?: ReturnType<typeof revision>; start_allowed: boolean; start_after?: unknown; replacement?: unknown; failure?: string; completed_at: string | null; observed_at: null; actor_id: string; created_at: string }
function assignment(id: string, n: number): Assignment { return { revision_id: id, digest: revision(id, n).digest, app_name: 'whoami', revision_number: n, revision: revision(id, n), generation: 1, activation_generation: 1, desired: 'present', replicas: 2, start_allowed: true, completed_at: null, observed_at: null, actor_id: owner, created_at: '2026-11-07T00:00:00Z' } }
function absent(a: Assignment) { a.desired = 'absent'; a.start_allowed = false; delete a.revision; delete a.replicas; delete a.start_after }
async function setup(page: Page) {
  const state = { admin: true, assignments: [] as Assignment[], posts: [] as { method: string; path: string; body: Record<string, unknown> }[], held: [] as Route[], hold: false, gen: 0, listingReads: 0 }
  await page.addInitScript(saved => {
    localStorage.setItem('sb-auth-auth-token', JSON.stringify(saved))
    const fetch = window.fetch.bind(window)
    window.fetch = (input, options) => fetch(input, String(input).startsWith('/api/') ? { ...options, signal: undefined } : options)
  }, saved)
  await page.route('http://auth.test/**', route => route.fulfill({ json: saved.user, headers: { 'Access-Control-Allow-Origin': '*' } }))
  await page.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname, method = route.request().method()
    if (path === '/api/orchestrators') return route.fulfill({ json: { orchestrators: [{ address: '0x1111111111111111111111111111111111111111', display_name: 'Test orchestrator' }] } })
    if (path === '/api/config') return route.fulfill({ json: { supabase_url: 'http://auth.test', supabase_publishable_key: 'fixture' } })
    if (path === '/api/operator/config') return route.fulfill({ json: { public_api_url: 'http://localhost:5173', secrets_url: secretsURL } })
    if (path === '/api/me') return route.fulfill({ json: { user_id: owner, is_admin: state.admin } })
    if (path === '/api/machines') return route.fulfill({ json: { machines: [] } })
    if (path === '/api/admin/administrators') return route.fulfill({ json: { administrators: [] } })
    if (path === '/api/admin/machines') return route.fulfill({ json: { machines: [{ node_id: node, hostname: 'worker-apps', orchestrator_address: owner, k3s_version: 'v1.37.2+k3s1', created_at: '2026-11-07T00:00:00Z', last_config_fetch_at: null }] } })
    if (path === '/api/admin/apps') return route.fulfill({ json: { apps: [{ name: 'whoami', head: revision(r2, 2), active_revision_count: 2 }], payment_mode: 'offchain', next_after_name: null } })
    if (path === '/api/admin/apps/whoami') return route.fulfill({ json: { revisions: [revision(r2, 2), revision(r1, 1)], next_before_revision: null } })
    if (path.startsWith('/api/admin/apps/whoami/revisions/')) return route.fulfill({ json: revision(path.endsWith(r1) ? r1 : r2, path.endsWith(r1) ? 1 : 2) })
    if (path === base && method === 'GET') {
      state.listingReads++
      if (state.hold) { state.held.push(route); return }
      const after = new URL(route.request().url()).searchParams.get('after_revision_id') || ''
      const remaining = [...state.assignments].sort((a, b) => a.revision_id.localeCompare(b.revision_id)).filter(a => a.revision_id > after)
      const assignments = remaining.slice(0, 100)
      return route.fulfill({ json: { assignments, apps_generation: state.gen, published_generation: 0, next_after_revision_id: remaining.length > 100 ? assignments.at(-1)!.revision_id : null, last_config_fetch_at: null } })
    }
    if (path.startsWith(base + '/') && method !== 'GET') {
      const body = route.request().postDataJSON(); state.posts.push({ method, path, body }); state.gen++
      const id = path.split('/')[6], old = state.assignments.find(a => a.revision_id === id)
      if (method === 'PUT') {
        if (old) { old.generation++; old.replicas = body.replicas }
        else state.assignments.push({ ...assignment(id, id === r1 ? 1 : 2), replicas: body.replicas })
      } else if (method === 'DELETE' && old) { absent(old); old.generation++ }
      else if (method === 'POST' && old) {
        absent(old); old.generation++
        state.assignments.push({ ...assignment(body.target.revision_id, 2), replicas: body.target.replicas, start_allowed: false, start_after: { source_revision_id: id, source_removal_generation: old.generation } })
      }
      return route.fulfill({ status: 202, json: { changed: true, assignments: state.assignments.filter(a => a.revision_id === id || a.revision_id === body.target?.revision_id) } })
    }
    return route.fulfill({ status: 404, json: { error: 'Not found' } })
  })
  await mockSecrets(page)
  await page.goto('/')
  await page.getByRole('button', { name: 'Manage apps for worker-apps' }).click()
  return state
}

test('machine apps assign, scale and replace only after cleanup', async ({ page }) => {
  const state = await setup(page)
  await page.getByLabel('Catalog app for machine').selectOption('whoami')
  await page.getByLabel('Catalog revision for machine').selectOption(r1)
  await page.getByRole('button', { name: 'Assign selected revision', exact: true }).click()
  await expect(page.getByText('Pending Runtime completion', { exact: true })).toBeVisible()
  expect(state.posts[0].body).toMatchObject({ expected_generation: 0, replicas: 2 })
  await page.getByLabel(`Replicas for ${r1}`).fill('3')
  await page.getByRole('button', { name: 'Save replicas', exact: true }).click()
  await expect.poll(() => state.assignments[0].replicas).toBe(3)
  await page.getByLabel('Catalog revision for machine').selectOption(r2)
  await page.getByRole('button', { name: 'Replace revision 1', exact: true }).click()
  await expect(page.getByText('Waiting for previous revision cleanup', { exact: true })).toBeVisible()
  await expect(page.getByText('Removing — waiting for cleanup', { exact: true })).toBeVisible()
  await expect(page.getByText('whoami / revision 1', { exact: true })).toBeVisible()
  expect(state.posts.at(-1)?.body).toMatchObject({ expected_generation: 2, target: { revision_id: r2, expected_generation: 0 } })
  await page.getByRole('button', { name: 'Remove revision 2', exact: true }).click()
  await expect.poll(() => state.assignments[1].desired).toBe('absent')
})

test('revocation unmounts app panel and ignores late assignment responses', async ({ page }) => {
  const state = await setup(page)
  await expect(page.getByText('No app assignments.', { exact: true })).toBeVisible()
  state.hold = true
  await page.getByRole('button', { name: 'Refresh assignments', exact: true }).click()
  await expect.poll(() => state.held.length).toBeGreaterThan(0)
  state.admin = false
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(page.getByRole('heading', { name: 'Apps on worker-apps' })).toHaveCount(0)
  for (const route of state.held) await route.fulfill({ json: { assignments: [], apps_generation: 99, published_generation: 99, next_after_revision_id: null } })
  await expect(page.getByRole('heading', { name: 'Apps on worker-apps' })).toHaveCount(0)
})


test('polling refreshes every loaded assignment page', async ({ page }) => {
  const state = await setup(page)
  await expect(page.getByText('No app assignments.', { exact: true })).toBeVisible()
  state.assignments = Array.from({ length: 101 }, (_, i) => {
    const id = `${(i + 1).toString(16).padStart(8, '0')}-0000-4000-8000-000000000001`
    const a = assignment(id, i + 1); absent(a); a.completed_at = '2026-11-07T00:00:00Z'; return a
  })
  await page.getByRole('button', { name: 'Refresh assignments', exact: true }).click()
  await page.getByRole('button', { name: 'More assignments', exact: true }).click()
  const last = state.assignments[100]
  const button = page.getByRole('button', { name: `Inspect assignment ${last.revision_id}`, exact: true })
  await expect(button).toBeVisible()
  last.generation = 2
  const reads = state.listingReads
  await expect.poll(() => state.listingReads, { timeout: 8000 }).toBeGreaterThan(reads + 1)
  await expect(button).toBeVisible()
  await expect(button.locator('..').locator('..')).toContainText('Desired 2')
})

test('manual assignment refresh supersedes an in-flight poll', async ({ page }) => {
  const state = await setup(page)
  await expect(page.getByText('No app assignments.', { exact: true })).toBeVisible()
  state.hold = true
  await page.getByRole('button', { name: 'Refresh assignments', exact: true }).click()
  await expect.poll(() => state.held.length).toBe(1)
  state.assignments = [assignment(r1, 1)]; state.hold = false
  await page.getByRole('button', { name: 'Refresh assignments', exact: true }).click()
  await expect(page.getByLabel(`Replicas for ${r1}`)).toHaveValue('2')
  await state.held[0].fulfill({ json: { assignments: [], apps_generation: 0, published_generation: 0, next_after_revision_id: null } })
  await expect(page.getByLabel(`Replicas for ${r1}`)).toHaveValue('2')
})

test('replica drafts clear after saving or a new activation and retain unrelated edits', async ({ page }) => {
  const state = await setup(page)
  state.assignments = [assignment(r1, 1), assignment(r2, 2)]
  await page.getByRole('button', { name: 'Refresh assignments', exact: true }).click()
  const first = page.getByLabel(`Replicas for ${r1}`), second = page.getByLabel(`Replicas for ${r2}`)
  await first.fill('3'); await second.fill('5')
  await first.locator('..').locator('..').getByRole('button', { name: 'Save replicas', exact: true }).click()
  await expect(first).toHaveValue('3'); await expect(second).toHaveValue('5')
  await expect(page.getByRole('button', { name: 'Refresh assignments', exact: true })).toBeEnabled()
  state.assignments[0].replicas = 4; state.assignments[0].generation++
  await page.getByRole('button', { name: 'Refresh assignments', exact: true }).click()
  await expect(first).toHaveValue('4'); await expect(second).toHaveValue('5')
  state.assignments[1].activation_generation = 3; state.assignments[1].generation = 3; state.assignments[1].replicas = 1
  await page.getByRole('button', { name: 'Refresh assignments', exact: true }).click()
  await expect(second).toHaveValue('1')
  await second.fill('7')
  state.assignments = [state.assignments[0]]
  await page.getByRole('button', { name: 'Refresh assignments', exact: true }).click()
  await expect(second).toHaveCount(0)
  state.assignments.push({ ...assignment(r2, 2), replicas: 6 })
  await page.getByRole('button', { name: 'Refresh assignments', exact: true }).click()
  await expect(second).toHaveValue('6')
})


test('rolling assignment reports failures before generic progress', async ({ page }) => {
  const state = await setup(page)
  const target = { ...assignment(r2, 2), replacement: { source_revision_id: r1, source_activation_generation: 1, source_removal_generation: 2, replica_limit: 2 } }
  state.assignments = [target]
  await page.getByRole('button', { name: 'Refresh assignments', exact: true }).click()
  await expect(page.getByText('Rolling replacement in progress', { exact: true })).toBeVisible()
  state.assignments[0].failure = 'startup_failed'
  await page.getByRole('button', { name: 'Refresh assignments', exact: true }).click()
  await expect(page.getByText('Failed: startup_failed', { exact: true })).toBeVisible()
  await expect(page.getByText('Rolling replacement in progress', { exact: true })).toHaveCount(0)
})
