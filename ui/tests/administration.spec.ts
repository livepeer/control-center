import { test, expect } from '@playwright/test'
import type { Page, Route } from '@playwright/test'

const a = '11111111-1111-4111-8111-111111111111'
const b = '22222222-2222-4222-8222-222222222222'
const grantA = { grant_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', email: 'a@example.invalid', current_email: 'renamed@example.invalid', user_id: a, state: 'bound', revision: 2 }
const grantB = { grant_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', email: 'b@example.invalid', current_email: null, user_id: b, state: 'bound', revision: 1 }
const fleet = { node_id: 'vkvkvkvkvkvkuaaaaaaaaaaaaa', hostname: 'private-fleet-machine', owner_id: b, k3s_version: 'v1.37.2+k3s1', created_at: '2026-11-06T00:00:00Z', last_config_fetch_at: null }
const expires = Math.floor(Date.now() / 1000) + 3600

function session(id: string) {
  return { access_token: `${Buffer.from('{}').toString('base64url')}.${Buffer.from(JSON.stringify({ sub: id, exp: expires })).toString('base64url')}.fixture`, refresh_token: `fixture-${id}`, token_type: 'bearer', expires_at: expires, expires_in: 3600, user: { id, email: id === a ? 'a@example.invalid' : 'b@example.invalid', aud: 'authenticated', role: 'authenticated', app_metadata: {}, user_metadata: { role: 'admin' }, created_at: '2026-11-06T00:00:00Z' } }
}

async function setup(page: Page, initialAdmin = true) {
  const state = { admin: initialAdmin, meStatus: 200, rejectMutation: false, gatewayError: null as { status: number; body: string } | null, missingAccount: false, grants: [grantA] as (typeof grantA | typeof grantB)[], holdFleet: false, heldFleet: null as Route | null, holdMe: false, heldMe: null as Route | null, posted: null as unknown }
  await page.addInitScript(({ saved }) => {
    localStorage.setItem('sb-auth-auth-token', JSON.stringify(saved))
    // Model an already-resolving response whose completion survives abort.
    const fetch = window.fetch.bind(window)
    window.fetch = (input, options) => fetch(input, String(input).startsWith('/api/') ? { ...options, signal: undefined } : options)
  }, { saved: session(a) })
  await page.route('http://auth.test/**', route => route.fulfill({ json: session(a).user, headers: { 'Access-Control-Allow-Origin': '*' } }))
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    const actor = route.request().headers().authorization === `Bearer ${session(b).access_token}` ? b : a
    if (path === '/api/config') return route.fulfill({ json: { supabase_url: 'http://auth.test', supabase_publishable_key: 'fixture-public', public_api_url: 'http://localhost:41932' } })
    if (path === '/api/bootstrap-token') return route.fulfill({ json: { token: 'fixture-enrollment', expires_at: new Date(Date.now() + 3600000).toISOString() } })
    if (path === '/api/machines') return route.fulfill({ json: { machines: [] } })
    if (path === '/api/me') {
      if (state.holdMe) { state.heldMe = route; return }
      return route.fulfill({ status: state.meStatus, json: state.meStatus === 200 ? { user_id: actor, is_admin: actor === a && state.admin } : { error: 'Capability service unavailable.' } })
    }
    if (path === '/api/admin/apps') return route.fulfill({ json: { apps: [], payment_mode: 'offchain', next_after_name: null } })
    if (path === '/api/admin/machines') {
      if (state.holdFleet) { state.heldFleet = route; return }
      return route.fulfill({ json: { machines: [fleet] } })
    }
    if (route.request().method() !== 'GET') {
      if (state.gatewayError) return route.fulfill({ ...state.gatewayError, contentType: 'text/html' })
      if (state.rejectMutation) { state.admin = false; return route.fulfill({ status: 403, json: { error: 'Administrator access is required.' } }) }
      if (state.missingAccount) return route.fulfill({ status: 404, json: { error: 'No eligible confirmed account has that email address.' } })
      if (route.request().method() === 'POST') {
        expect(route.request().headers()['content-type']).toBe('application/json')
        state.posted = route.request().postDataJSON(); state.grants = [grantA, grantB]
        return route.fulfill({ status: 201, json: grantB })
      }
      state.grants = [grantA]; return route.fulfill({ status: 204 })
    }
    return route.fulfill({ json: { administrators: state.grants } })
  })
  const capability = page.waitForResponse(response => response.url().endsWith('/api/me'))
  await page.goto('/')
  await (await capability).finished()
  await settled(page)
  return state
}

async function settled(page: Page) {
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))))
}

test('ordinary users do not see admin controls despite editable role metadata', async ({ page }) => {
  await setup(page, false)
  await expect(page.getByRole('heading', { name: 'Your machines', level: 2 })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Administration', exact: true })).toHaveCount(0)
  await expect(page.getByText('private-fleet-machine')).toHaveCount(0)
})

test('admin can grant and revoke another account, but self-revocation is disabled by UUID', async ({ page }, testInfo) => {
  const state = await setup(page)
  await expect(page.getByRole('heading', { name: 'Administration', exact: true })).toBeVisible()
  await expect(page.getByText('private-fleet-machine')).toBeVisible()
  await expect(page.getByRole('listitem').filter({ hasText: 'renamed@example.invalid' }).getByRole('button', { name: 'Revoke' })).toBeDisabled()
  await page.getByLabel('Existing account email').fill('b@example.invalid')
  await page.getByRole('button', { name: 'Grant access' }).click()
  await expect(page.getByRole('listitem').filter({ hasText: 'b@example.invalid' })).toBeVisible()
  expect(state.posted).toEqual({ email: 'b@example.invalid' })
  await page.screenshot({ path: testInfo.outputPath('administration.png'), fullPage: true })
  await page.getByRole('listitem').filter({ hasText: 'b@example.invalid' }).getByRole('button', { name: 'Revoke' }).click()
  await expect(page.getByRole('listitem').filter({ hasText: 'b@example.invalid' })).toHaveCount(0)
})

test('capability outage clears privileged data while preserving the owner console', async ({ page }) => {
  const state = await setup(page)
  await expect(page.getByText('private-fleet-machine')).toBeVisible()
  state.meStatus = 503
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(page.getByText('private-fleet-machine')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Grant access' })).toHaveCount(0)
  await expect(page.getByRole('alert')).toContainText('Capability service unavailable.')
  await expect(page.getByRole('heading', { name: 'Your machines', level: 2 })).toBeVisible()
})

test('late fleet success cannot restore data after same-session authorization loss', async ({ page }) => {
  const state = await setup(page)
  await expect(page.getByText('private-fleet-machine')).toBeVisible()
  state.holdFleet = true
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect.poll(() => state.heldFleet !== null).toBe(true)
  state.rejectMutation = true
  await page.getByLabel('Existing account email').fill('b@example.invalid')
  await page.getByRole('button', { name: 'Grant access' }).click()
  await expect(page.getByRole('heading', { name: 'Administration', exact: true })).toHaveCount(0)
  const late = page.waitForResponse(response => response.url().endsWith('/api/admin/machines'))
  await state.heldFleet!.fulfill({ json: { machines: [{ ...fleet, hostname: 'obsolete-secret' }] } })
  await (await late).finished(); await settled(page)
  await expect(page.getByText('obsolete-secret')).toHaveCount(0)
  await expect(page.getByText('private-fleet-machine')).toHaveCount(0)
})

test('a delayed capability response from a previous account is ignored', async ({ page }) => {
  const state = await setup(page)
  await expect(page.getByText('private-fleet-machine')).toBeVisible()
  state.holdMe = true
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect.poll(() => state.heldMe !== null).toBe(true)
  state.holdMe = false
  await page.evaluate(saved => {
    localStorage.setItem('sb-auth-auth-token', JSON.stringify(saved))
    new BroadcastChannel('sb-auth-auth-token').postMessage({ event: 'SIGNED_IN', session: saved })
  }, session(b))
  await expect(page.locator('.account-email')).toHaveText('b@example.invalid')
  const late = page.waitForResponse(response => response.url().endsWith('/api/me'))
  await state.heldMe!.fulfill({ json: { user_id: a, is_admin: true } })
  await (await late).finished(); await settled(page)
  await expect(page.getByText('private-fleet-machine')).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'Administration', exact: true })).toHaveCount(0)
})

test('grant errors remain visible after inventory refresh', async ({ page }) => {
  const state = await setup(page)
  await expect(page.getByText('private-fleet-machine')).toBeVisible()
  state.missingAccount = true
  await page.getByLabel('Existing account email').fill('missing@example.invalid')
  const refreshed = page.waitForResponse(response => response.url().endsWith('/api/admin/administrators') && response.request().method() === 'GET')
  await page.getByRole('button', { name: 'Grant access' }).click()
  await (await refreshed).finished(); await settled(page)
  await expect(page.getByRole('alert')).toContainText('No eligible confirmed account')
  await expect(page.getByRole('button', { name: 'Grant access' })).toBeEnabled()
})

test('sign-out ignores a pending fleet response', async ({ page }) => {
  const state = await setup(page)
  await expect(page.getByText('private-fleet-machine')).toBeVisible()
  state.holdFleet = true
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect.poll(() => state.heldFleet !== null).toBe(true)
  await page.getByRole('button', { name: 'Sign out' }).click()
  await expect(page.getByLabel('Email address')).toBeVisible()
  const late = page.waitForResponse(response => response.url().endsWith('/api/admin/machines'))
  await state.heldFleet!.fulfill({ json: { machines: [fleet] } })
  await (await late).finished(); await settled(page)
  await expect(page.getByText('private-fleet-machine')).toHaveCount(0)
})

for (const status of [401,403,503]) {
  test(`non-JSON ${status} mutation error clears controls before capability refresh finishes`, async ({ page }) => {
    const state = await setup(page)
    await expect(page.getByText('private-fleet-machine')).toBeVisible()
    state.holdMe = true
    state.gatewayError = { status, body: status === 401 ? '' : '<h1>Gateway error</h1>' }
    await page.getByLabel('Existing account email').fill('b@example.invalid')
    await page.getByRole('button', { name: 'Grant access' }).click()
    await expect.poll(() => state.heldMe !== null).toBe(true)
    await expect(page.getByRole('button', { name: 'Grant access' })).toHaveCount(0)
    await expect(page.getByText('private-fleet-machine')).toHaveCount(0)
    if (status === 503) await expect(page.getByRole('alert')).toContainText('The request failed. Please try again.')
    await state.heldMe!.fulfill({ json: { user_id: a, is_admin: false } })
  })
}
