import { test, expect } from '@playwright/test'
import type { Page, Route } from '@playwright/test'
import { mockSecrets, secretsURL } from './secrets-fixture'

const a = '0x1111111111111111111111111111111111111111'
const b = '0x2222222222222222222222222222222222222222'
const user = '11111111-1111-4111-8111-111111111111'
const other = '22222222-2222-4222-8222-222222222222'
const token = 'signed-invitation-fixture'
const groups = [{ address: a, display_name: 'Alpha' }, { address: b, display_name: 'Beta' }]
function session() {
  const exp = Math.floor(Date.now() / 1000) + 3600
  return { access_token: `e30.${Buffer.from(JSON.stringify({ sub: user, exp })).toString('base64url')}.fixture`, refresh_token: 'fixture', token_type: 'bearer', expires_at: exp, expires_in: 3600, user: { id: user, email: 'member@example.invalid', aud: 'authenticated', role: 'authenticated', app_metadata: {}, user_metadata: {}, created_at: '2026-11-06T00:00:00Z' } }
}

async function setup(page: Page, { signedIn = true, empty = false } = {}) {
  const saved = session()
  const state = { groups: empty ? [] : [...groups], members: [{ user_id: user, email: 'member@example.invalid' }], requests: [] as string[], accepted: [] as string[], removed: [] as string[], previewFailure: 0, acceptFailure: 0, holdMembers: false, heldMembers: null as Route | null, holdInvitation: false, heldInvitation: null as Route | null }
  await page.addInitScript(({ saved, signedIn }) => {
    if (signedIn) localStorage.setItem('sb-auth-auth-token', JSON.stringify(saved))
    const original = window.fetch.bind(window)
    window.fetch = (input, options) => original(input, { ...options, signal: undefined })
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (text: string) => { document.documentElement.dataset.clipboard = text } } })
  }, { saved, signedIn })
  await page.route('http://auth.test/**', route => {
    const path = new URL(route.request().url()).pathname
    const headers = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*' }
    if (route.request().method() === 'OPTIONS') return route.fulfill({ status: 204, headers })
    if (path.endsWith('/authorize')) return route.fulfill({ status: 302, headers: { ...headers, Location: 'http://localhost:5173/auth/callback?code=fixture-code' } })
    if (path.endsWith('/signup')) return route.fulfill({ json: { user: saved.user }, headers })
    if (path.endsWith('/token')) return route.fulfill({ json: saved, headers })
    return route.fulfill({ json: saved.user, headers })
  })
  await page.route('**/api/**', route => {
    const req = route.request(), path = new URL(req.url()).pathname
    state.requests.push(req.url())
    if (path === '/api/config') return route.fulfill({ json: { supabase_url: 'http://auth.test', supabase_publishable_key: 'fixture' } })
    if (path === '/api/operator/config') return route.fulfill({ json: { public_api_url: 'https://api.example', mode: 'offchain', secrets_url: secretsURL } })
    if (path === '/api/operator/apps') return route.fulfill({ json: { apps: [] } })
    if (path === '/api/orchestrators') return route.fulfill({ json: { orchestrators: state.groups } })
    if (path === '/api/me') return route.fulfill({ json: { user_id: user, is_admin: false } })
    if (path === '/api/machines') return route.fulfill({ json: { machines: [] } })
    if (path === '/api/bootstrap-token') return route.fulfill({ json: { token: 'bootstrap-fixture', expires_at: new Date(Date.now() + 3600000).toISOString() } })
    if (path.endsWith('/members') && req.method() === 'GET') {
      if (state.holdMembers && path.includes(a)) { state.heldMembers = route; return }
      return route.fulfill({ json: { members: state.members } })
    }
    if (req.method() === 'DELETE') {
      const target = path.split('/').at(-1)!
      state.removed.push(target)
      state.members = state.members.filter(m => m.user_id !== target)
      if (target === user) state.groups = state.groups.filter(o => !path.includes(o.address))
      return route.fulfill({ status: 204 })
    }
    if (path.endsWith('/invitations')) {
      if (state.holdInvitation) { state.heldInvitation = route; return }
      return route.fulfill({ json: { token, expires_at: new Date(Date.now() + 86400000).toISOString() } })
    }
    if (path === '/api/orchestrator-invitations/preview') {
      expect(req.postDataJSON()).toEqual({ token })
      expect(req.headers().authorization).toBe(`Bearer ${saved.access_token}`)
      return route.fulfill(state.previewFailure ? { status: state.previewFailure, json: { error: 'This invitation is invalid or has expired.' } } : { json: { ...groups[0], expires_at: new Date(Date.now() + 86400000).toISOString() } })
    }
    if (path === '/api/orchestrator-invitations/accept') {
      state.accepted.push(req.postDataJSON().token)
      if (state.acceptFailure) return route.fulfill({ status: state.acceptFailure, json: { error: 'This invitation has already been accepted.', code: 'invitation_used' } })
      if (!state.groups.some(o => o.address === a)) state.groups.push(groups[0])
      return route.fulfill({ json: { address: a } })
    }
    return route.fulfill({ status: 404, json: { error: 'Unexpected route' } })
  })
  await mockSecrets(page)
  return state
}

test('last member cannot leave and can copy a 24-hour invitation link', async ({ page }, testInfo) => {
  const state = await setup(page)
  await page.goto('/')
  await page.getByText('Members', { exact: true }).click()
  await expect(page.getByRole('button', { name: 'Leave orchestrator' })).toBeDisabled()
  await expect(page.getByText('You are the last member.', { exact: false })).toBeVisible()
  await page.getByRole('button', { name: 'Create invitation link' }).click()
  await expect(page.getByLabel('Invitation link', { exact: true })).toHaveValue(`http://localhost:5173/invite#token=${token}`)
  await expect(page.getByText('(24 hours after creation).', { exact: false })).toBeVisible()
  await page.getByRole('button', { name: 'Copy invitation link' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-clipboard', `http://localhost:5173/invite#token=${token}`)
  expect(state.requests.some(url => url.includes(token))).toBe(false)
  await page.screenshot({ path: testInfo.outputPath('members-desktop.png'), fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.locator('.topbar')).toHaveCount(1)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.screenshot({ path: testInfo.outputPath('members-mobile.png') })
})

test('members can remove another member or leave and switch to another orchestrator', async ({ page }) => {
  const state = await setup(page)
  state.members.push({ user_id: other, email: 'other@example.invalid' })
  await page.goto('/')
  await page.getByText('Members', { exact: true }).click()
  page.on('dialog', dialog => dialog.accept())
  await page.getByRole('button', { name: 'Remove member', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Leave orchestrator' })).toBeDisabled()
  expect(state.removed).toEqual([other])
  state.members.push({ user_id: other, email: 'other@example.invalid' })
  await page.evaluate(() => window.dispatchEvent(new Event('focus')))
  await expect(page.getByRole('button', { name: 'Leave orchestrator' })).toBeEnabled()
  await page.getByRole('button', { name: 'Leave orchestrator' }).click()
  await expect(page.getByRole('combobox', { name: 'Orchestrator' })).toHaveValue(b)
  expect(state.removed).toEqual([other, user])
})

test('acceptance is explicit, works without existing orchestrators, and selects the joined workspace', async ({ page }) => {
  const state = await setup(page, { empty: true })
  await page.goto(`/invite#token=${token}`)
  const invite = page.getByRole('region', { name: 'Orchestrator invitation' })
  await expect(invite.getByText('member@example.invalid', { exact: true })).toBeVisible()
  await expect(invite.getByText(a, { exact: true })).toBeVisible()
  expect(state.accepted).toEqual([])
  expect(page.url()).not.toContain(token)
  await invite.getByRole('button', { name: 'Accept invitation' }).click()
  await expect(page.getByRole('combobox', { name: 'Orchestrator' })).toHaveValue(a)
  await expect(invite).toHaveCount(0)
  expect(state.accepted).toEqual([token])
  expect(await page.evaluate(() => sessionStorage.getItem('lpcc-pending-invitation'))).toBeNull()
  expect(state.requests.some(url => url.includes(token))).toBe(false)
})

for (const method of ['password', 'signup', 'google']) test(`invitation survives ${method} authentication`, async ({ page }) => {
  await setup(page, { signedIn: false, empty: true })
  await page.goto(`/invite#token=${token}`)
  await expect(page.getByLabel('Email address')).toBeVisible()
  if (method === 'google') await page.getByRole('button', { name: 'Continue with Google' }).click()
  else {
    if (method === 'signup') {
      await page.getByRole('button', { name: 'Create an account', exact: true }).click()
      await page.getByLabel('Email address').fill('member@example.invalid')
      await page.getByLabel('Password', { exact: false }).fill('test-password')
      await page.getByRole('button', { name: 'Create account', exact: true }).click()
      await expect(page.getByText('Check your email to confirm your account, then come back to sign in.')).toBeVisible()
      await page.reload()
    }
    await page.getByLabel('Email address').fill('member@example.invalid')
    await page.getByLabel('Password', { exact: false }).fill('test-password')
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  }
  await expect(page.getByRole('button', { name: 'Accept invitation', exact: true })).toBeVisible()
  expect(await page.evaluate(() => sessionStorage.getItem('lpcc-pending-invitation'))).toBe(token)
})

test('expired and already-used invitations show server errors', async ({ page }) => {
  const state = await setup(page)
  state.previewFailure = 400
  await page.goto(`/invite#token=${token}`)
  await expect(page.getByRole('alert')).toContainText('invalid or has expired')
  await expect(page.getByRole('button', { name: 'Accept invitation', exact: true })).toHaveCount(0)
  state.previewFailure = 0; state.acceptFailure = 409
  await page.getByRole('button', { name: 'Retry invitation' }).click()
  await page.getByRole('button', { name: 'Accept invitation', exact: true }).click()
  await expect(page.getByRole('alert')).toContainText('already been accepted')
  await page.getByRole('button', { name: 'Dismiss invitation' }).click()
  await expect(page.getByRole('region', { name: 'Orchestrator invitation' })).toHaveCount(0)
})

test('member lists and generated links ignore responses from the previous orchestrator', async ({ page }) => {
  const state = await setup(page)
  state.holdMembers = true
  await page.goto('/')
  await page.getByText('Members', { exact: true }).click()
  await expect.poll(() => state.heldMembers !== null).toBe(true)
  await page.getByRole('combobox', { name: 'Orchestrator' }).selectOption(b)
  await page.getByText('Members', { exact: true }).click()
  await state.heldMembers!.fulfill({ json: { members: [{ user_id: other, email: 'obsolete@example.invalid' }] } })
  await expect(page.getByText('obsolete@example.invalid')).toHaveCount(0)
  state.holdInvitation = true
  await page.getByRole('button', { name: 'Create invitation link' }).click()
  await expect.poll(() => state.heldInvitation !== null).toBe(true)
  state.holdMembers = false
  await page.getByRole('combobox', { name: 'Orchestrator' }).selectOption(a)
  await state.heldInvitation!.fulfill({ json: { token: 'obsolete-token', expires_at: new Date(Date.now() + 86400000).toISOString() } })
  await page.getByText('Members', { exact: true }).click()
  await expect(page.getByLabel('Invitation link', { exact: true })).toHaveCount(0)
})

test('a delayed member refresh cannot restore someone removed by a newer mutation', async ({ page }) => {
  const state = await setup(page)
  state.members.push({ user_id: other, email: 'other@example.invalid' })
  await page.goto('/')
  await page.getByText('Members', { exact: true }).click()
  await expect(page.getByRole('button', { name: 'Remove member', exact: true })).toBeVisible()
  const stale = [...state.members]
  let held: Route | null = null
  await page.route(`**/api/orchestrators/${a}/members`, route => { held = route }, { times: 1 })
  await page.evaluate(() => window.dispatchEvent(new Event('focus')))
  await expect.poll(() => held !== null).toBe(true)
  page.on('dialog', dialog => dialog.accept())
  await page.getByRole('button', { name: 'Remove member', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Leave orchestrator' })).toBeDisabled()
  await held!.fulfill({ json: { members: stale } })
  await expect(page.getByRole('button', { name: 'Remove member', exact: true })).toHaveCount(0)
})

test('an invitation opened in an already-running tab is captured', async ({ page }) => {
  await setup(page)
  await page.goto('/invite')
  await expect(page.getByRole('combobox', { name: 'Orchestrator' })).toHaveValue(a)
  await page.evaluate(value => { window.location.hash = `token=${value}` }, token)
  await expect(page.getByRole('button', { name: 'Accept invitation', exact: true })).toBeVisible()
  expect(page.url()).not.toContain(token)
})

test('an older acceptance cannot dismiss a newer invitation during workspace refresh', async ({ page }) => {
  await setup(page, { empty: true })
  await page.goto(`/invite#token=${token}`)
  await expect(page.getByRole('button', { name: 'Accept invitation', exact: true })).toBeVisible()
  await expect(page.getByRole('combobox', { name: 'Orchestrator' })).toBeDisabled()
  let held: Route | null = null
  await page.route('**/api/orchestrators', route => { held = route }, { times: 1 })
  await page.getByRole('button', { name: 'Accept invitation', exact: true }).click()
  await expect.poll(() => held !== null).toBe(true)
  const nextToken = 'another-invitation-fixture'
  await page.route('**/api/orchestrator-invitations/preview', route => route.fulfill({ json: { ...groups[1], expires_at: new Date(Date.now() + 86400000).toISOString() } }))
  await page.evaluate(value => { window.location.hash = `token=${value}` }, nextToken)
  const invite = page.getByRole('region', { name: 'Orchestrator invitation' })
  await expect(invite.getByText(b, { exact: true })).toBeVisible()
  await held!.fulfill({ json: { orchestrators: [groups[0]] } })
  await expect(page.getByRole('combobox', { name: 'Orchestrator' })).toHaveValue(a)
  await expect(invite.getByText(b, { exact: true })).toBeVisible()
  expect(await page.evaluate(() => sessionStorage.getItem('lpcc-pending-invitation'))).toBe(nextToken)
})

for (const failure of ['unavailable', 'superseded']) test(`acceptance selection survives a ${failure} workspace refresh`, async ({ page }) => {
  const state = await setup(page)
  await page.goto(`/invite#token=${token}`)
  const selector = page.getByRole('combobox', { name: 'Orchestrator' })
  await expect(selector).toHaveValue(a)
  await selector.selectOption(b)
  let held: Route | null = null
  await page.route('**/api/orchestrators', route => { held = route }, { times: 1 })
  await page.getByRole('button', { name: 'Accept invitation', exact: true }).click()
  await expect.poll(() => held !== null).toBe(true)
  if (failure === 'unavailable') {
    await held!.fulfill({ status: 503, json: { error: 'Membership service unavailable.' } })
    await expect(page.getByRole('button', { name: 'Accept invitation', exact: true })).toHaveCount(0)
    await page.getByRole('button', { name: 'Retry orchestrators' }).click()
  } else {
    await page.evaluate(() => window.dispatchEvent(new Event('focus')))
    await expect(selector).toHaveValue(a)
    await held!.fulfill({ json: { orchestrators: state.groups } })
  }
  await expect(selector).toHaveValue(a)
  expect(state.accepted).toEqual([token])
  // An explicit choice overrides the completed invitation's preference.
  await selector.selectOption(b)
  await page.evaluate(() => window.dispatchEvent(new Event('focus')))
  await expect(selector).toHaveValue(b)
})

for (const stage of ['acceptance', 'workspace refresh']) test(`session renewal during ${stage} preserves invitation success`, async ({ page }) => {
  const state = await setup(page)
  await page.goto(`/invite#token=${token}`)
  const selector = page.getByRole('combobox', { name: 'Orchestrator' })
  await expect(selector).toHaveValue(a)
  await selector.selectOption(b)
  let held: Route | null = null
  if (stage === 'acceptance') {
    await page.route('**/api/orchestrator-invitations/accept', route => {
      state.accepted.push(route.request().postDataJSON().token)
      held = route
    })
  } else await page.route('**/api/orchestrators', route => { held = route }, { times: 1 })
  // Once acceptance commits, re-previewing would report an already-used link.
  await page.route('**/api/orchestrator-invitations/preview', route => route.fulfill({ status: 409, json: { error: 'This invitation has already been accepted.', code: 'invitation_used' } }))
  await page.getByRole('button', { name: 'Accept invitation', exact: true }).click()
  await expect.poll(() => held !== null).toBe(true)
  const refreshed = page.waitForResponse(response => new URL(response.url()).pathname === '/api/orchestrators' && response.request().headers().authorization?.endsWith('.renewed') === true)
  await page.evaluate(() => {
    const saved = JSON.parse(localStorage.getItem('sb-auth-auth-token')!)
    saved.access_token = saved.access_token.replace(/\.[^.]+$/, '.renewed')
    localStorage.setItem('sb-auth-auth-token', JSON.stringify(saved))
    new BroadcastChannel('sb-auth-auth-token').postMessage({ event: 'TOKEN_REFRESHED', session: saved })
  })
  await (await refreshed).finished()
  await held!.fulfill({ json: stage === 'acceptance' ? { address: a } : { orchestrators: state.groups } })
  await expect(selector).toHaveValue(a)
  await expect(page.getByRole('region', { name: 'Orchestrator invitation' })).toHaveCount(0)
  await expect(page.getByText('This invitation has already been accepted.')).toHaveCount(0)
  expect(state.accepted).toEqual([token])
})
