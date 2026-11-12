import { test, expect } from '@playwright/test'
import type { Page } from '@playwright/test'

async function onboard(page: Page, apiURL: string, token = 'header.payload.signature') {
  const expires = Math.floor(Date.now() / 1000) + 3600
  const session = {
    access_token: `${Buffer.from('{}').toString('base64url')}.${Buffer.from(JSON.stringify({ exp: expires })).toString('base64url')}.fixture`,
    refresh_token: 'fixture-refresh', token_type: 'bearer', expires_at: expires, expires_in: 3600,
    user: { id: '11111111-1111-4111-8111-111111111111', email: 'owner@example.invalid', aud: 'authenticated',
      role: 'authenticated', app_metadata: {}, user_metadata: {}, created_at: '2026-11-06T00:00:00Z' },
  }
  await page.addInitScript(saved => {
    localStorage.setItem('sb-auth-auth-token', JSON.stringify(saved))
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (text: string) => {
      document.documentElement.dataset.clipboard = text
    } } })
  }, session)
  await page.route('http://auth.test/**', route => route.fulfill({ json: session.user, headers: { 'Access-Control-Allow-Origin': '*' } }))
  await page.route('**/api/**', route => {
    switch (new URL(route.request().url()).pathname) {
      case '/api/config': return route.fulfill({ json: { supabase_url: 'http://auth.test', supabase_publishable_key: 'fixture', public_api_url: apiURL } })
      case '/api/bootstrap-token': return route.fulfill({ json: { token, expires_at: new Date(expires * 1000).toISOString() } })
      case '/api/machines': return route.fulfill({ json: { machines: [] } })
      case '/api/me': return route.fulfill({ json: { user_id: session.user.id, is_admin: false } })
      default: return route.fulfill({ status: 404, json: { error: 'Unexpected request' } })
    }
  })
  await page.goto('/')
  await expect(page.getByRole('button', { name: 'Copy command' })).toBeEnabled()
}

test('standard deployment copies a hosted POSIX command with only the environment token', async ({ page }) => {
  await onboard(page, 'https://controlcenter-api.livepeer.live/')
  const expected = "curl -fsSL 'http://localhost:5173/bootstrap.sh' | LIVEPEER_ENROLLMENT_TOKEN='header.payload.signature' sh -"
  await expect(page.getByLabel('Bootstrap command')).toHaveText(expected)
  await page.getByRole('button', { name: 'Copy command' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-clipboard', expected)
  await expect(page.getByText('POSIX SH', { exact: true })).toBeVisible()
  await expect(page.getByText('Prepare the host tools', { exact: true })).toBeVisible()
  await expect(page.getByText('Run as root', { exact: true })).toBeVisible()
  await expect(page.getByText('Set your API address', { exact: true })).toHaveCount(0)
  await expect(page.getByText('Open the runtime directory', { exact: true })).toHaveCount(0)
})

test('custom deployment includes its API override on the execution side and quotes shell input', async ({ page }) => {
  await onboard(page, 'https://custom.example/api/', "fixture'with-quote")
  await expect(page.getByLabel('Bootstrap command')).toHaveText(
    "curl -fsSL 'http://localhost:5173/bootstrap.sh' | LIVEPEER_API_URL='https://custom.example/api' LIVEPEER_ENROLLMENT_TOKEN='fixture'\\''with-quote' sh -",
  )
  await expect(page.getByLabel('Bootstrap command')).not.toContainText('LIVEPEER_RUNTIME_IMAGE')
  await expect(page.getByLabel('Bootstrap command')).not.toContainText('--token')
})
