import { mockSecrets, secretsURL } from './secrets-fixture'
import { test, expect } from '@playwright/test'
import type { Page, Route } from '@playwright/test'
import type { MachineObservation } from '../src/machine-status'

const user = '11111111-1111-4111-8111-111111111111'
const node = 'vkvkvkvkvkvkuaaaaaaaaaaaaa'
const revision = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const digest = `sha256:${'a'.repeat(64)}`
const session = { access_token: `${Buffer.from('{}').toString('base64url')}.${Buffer.from(JSON.stringify({ sub: user, exp: Math.floor(Date.now() / 1000) + 3600 })).toString('base64url')}.fixture`, refresh_token: 'fixture', token_type: 'bearer', expires_at: Math.floor(Date.now() / 1000) + 3600, expires_in: 3600, user: { id: user, email: 'owner@example.invalid', aud: 'authenticated', role: 'authenticated', app_metadata: {}, user_metadata: {}, created_at: '2026-11-09T00:00:00Z' } }
const machine = { node_id: node, hostname: 'worker-status', k3s_version: 'v1.37.2+k3s1', orchestrator_address: user, created_at: '2026-11-09T00:00:00Z', last_config_fetch_at: null, report_state: 'observed', terminal: false }

function evidence(): MachineObservation {
  const stamp = new Date().toISOString(), expires = new Date(Date.now() + 120000).toISOString()
  const stage = { generation: 1, apps_digest: digest, artifact_digest: digest }
  return { node_id: node, hostname: machine.hostname, lifecycle: 'active', rollout_generation: 1, requested: { generation: 2 }, delivered: stage, delivered_at: stamp, assignments_omitted: false, server_time: stamp,
    components: [
      { component: 'runtime', generation: 1, observed_at: stamp, received_at: stamp, expires_at: expires, fresh: true, current: true, ready: true, reason: 'ready', clock_uncertain: false, downloaded: stage, downloaded_at: stamp },
      { component: 'runner', generation: 1, observed_at: stamp, received_at: stamp, expires_at: expires, fresh: true, current: true, ready: true, reason: 'ready', clock_uncertain: false, apps: { owner_recreated_at: '0001-01-01T00:00:00Z', desired_generation: 1, desired_digest: digest, staged: stage, published: stage, applied: stage, instances_total: 1, instances_omitted: 0, assignments: [{ revision_id: revision, generation: 1, activation_generation: 1, instances: 1, ready: 1, registered: 1, cleanup_pending: 0, node_expires_at: expires, probe_expires_at: expires }], instances: [{ revision_id: revision, generation: 1, activation_generation: 1, instance_id: 'instance-preserved', pod_uid: 'pod-preserved', runner_id: 'runner-preserved', app_id: 'app-preserved', phase: 'running', ready: true, registered: true, capacity: 4, sessions: 2, node_observed_at: stamp, node_expires_at: expires, startup_deadline: expires, probe: { observed_at: stamp, due_at: expires, expires_at: expires, success: true, failures: 0, started: true } }] } },
      { component: 'app-reconciler', observer_id: 'reconciler-process-1', observer_started_at: stamp, generation: 1, observed_at: stamp, received_at: stamp, expires_at: expires, fresh: true, current: true, ready: true, reason: 'ready', clock_uncertain: false },
      { component: 'connector', generation: 1, observed_at: stamp, received_at: stamp, expires_at: expires, connector_observed_at: stamp, connector_expires_at: expires, fresh: true, current: true, ready: true, reason: 'ready', clock_uncertain: false },
    ],
    assignments: [{ revision_id: revision, digest, name: 'whoami', version: '1', revision: 1, generation: 1, activation_generation: 1, desired: 'present', replicas: 1, start_allowed: true, completed_at: stamp, health: { type: 'http', interval: '5s', timeout: '2s', failure_threshold: 3 } }],
    tunnel: { enabled: true, ready: true, reason: 'ready', verified_at: stamp, expires_at: expires, cleanup_complete: false }, discovery_enabled: true, discovery_initialized: true, discovery_selection_stale: false, discovery_selection_expires_at: expires,
    discovery_source: { state: 'fresh', selection_reason: 'selected', stale: false, expires_at: expires, failures: 0, last_success: stamp, transport_outcome: 'response_received', publication_blocked: false }, membership: { 'instance-preserved': { state: 'present', queried_at: stamp, observed_at: stamp, expires_at: expires } }, external_reachability: 'unverified' }
}

async function setup(page: Page, admin = false, reportState = 'observed', terminal = false) {
  const listedMachine = { ...machine, report_state: reportState, terminal }
  const state = { view: evidence(), fail: false, hold: false, held: [] as Route[], reads: 0, statusNodes: [] as string[], writes: [] as string[], admin }
  if (terminal) { state.view.lifecycle = 'cleanup_pending'; state.view.assignments[0].desired = 'absent'; state.view.assignments[0].completed_at = null }
  await page.addInitScript(saved => {
    localStorage.setItem('sb-auth-auth-token', JSON.stringify(saved))
    const fetch = window.fetch.bind(window)
    window.fetch = (input, options) => fetch(input, String(input).includes('/status') ? { ...options, signal: undefined } : options)
  }, session)
  await page.route('http://auth.test/**', route => route.fulfill({ json: session.user, headers: { 'Access-Control-Allow-Origin': '*' } }))
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/orchestrators') return route.fulfill({ json: { orchestrators: [{ address: '0x1111111111111111111111111111111111111111', display_name: 'Test orchestrator' }] } })
    if (route.request().method() !== 'GET') state.writes.push(path)
    if (path === '/api/config') return route.fulfill({ json: { supabase_url: 'http://auth.test', supabase_publishable_key: 'fixture' } })
    if (path === '/api/operator/config') return route.fulfill({ json: { public_api_url: 'https://api.example', secrets_url: secretsURL } })
    if (path === '/api/bootstrap-token') return route.fulfill({ json: { token: 'fixture', expires_at: new Date(Date.now() + 3600000).toISOString() } })
    if (path === '/api/me') return route.fulfill({ json: { user_id: user, is_admin: state.admin } })
    if (path === '/api/admin/administrators') return route.fulfill({ json: { administrators: [] } })
    if (path === '/api/admin/apps') return route.fulfill({ json: { apps: [], onchain_mode: 'offchain', next_after_name: null } })
    if (path === '/api/admin/machines') return route.fulfill({ json: { machines: [listedMachine] } })
    if (path === '/api/machines') return route.fulfill({ json: { machines: admin ? [] : [listedMachine, { ...machine, node_id: 'xo53xo53xo53waaaaaaaaaaaaa', hostname: 'second-worker', }] } })
    if (path.startsWith('/api/admin/machines/') && path.endsWith('/apps')) return route.fulfill({ json: { assignments: [], apps_generation: 2, published_generation: 1, next_after_revision_id: null, last_config_fetch_at: null } })
    if (path.endsWith('/status')) {
      state.reads++
      state.statusNodes.push(path.split('/').at(-2) || '')
      if (state.hold) { state.held.push(route); return }
      if (state.fail) return route.fulfill({ status: 503, json: { error: 'Status refresh unavailable.' } })
      const identity = path.includes('xo53xo53xo53waaaaaaaaaaaaa') ? { node_id: 'xo53xo53xo53waaaaaaaaaaaaa', hostname: 'second-worker' } : {}
      return route.fulfill({ json: { ...state.view, ...identity } })
    }
    return route.fulfill({ status: 404, json: { error: 'Not found' } })
  })
  await mockSecrets(page)
  await page.goto('/')
  await page.getByRole('button', { name: admin ? 'Inspect Runtime for worker-status' : 'View status for worker-status' }).click()
  await expect(page.getByRole('heading', { name: 'Runtime status on worker-status' })).toBeVisible()
  await expect(page.getByText('External app reachability: unverified.', { exact: false })).toBeVisible()
  return state
}

for (const admin of [false, true]) test(`${admin ? 'administrator' : 'owner'} sees distinct rollout and configured-health evidence`, async ({ page }, info) => {
  await setup(page, admin)
  const panel = page.getByRole('region', { name: 'Runtime status for worker-status' })
  await expect(panel.getByText('App generation 2', { exact: true })).toBeVisible()
  await expect(panel.getByText('Resource reconciliation confirmed', { exact: false })).toBeVisible()
  await expect(panel.getByText('HTTP readiness · every 5s · timeout 2s · 3 failures', { exact: false })).toBeVisible()
  await panel.getByText('Instance evidence and correlation (1)').click()
  await expect(panel.getByText('Present in published inventory', { exact: false })).toBeVisible()
  await expect(panel.getByText('runner-preserved', { exact: false })).toBeVisible()
  await expect(panel.getByText('reconciler-process-1', { exact: true })).toBeVisible()
  await expect(panel.getByText('Node registration was recreated at', { exact: false })).toHaveCount(0)
  if (!admin) await expect(page.getByRole('button', { name: 'Assign selected revision', exact: true })).toHaveCount(0)
  await page.screenshot({ path: info.outputPath('runtime-status.png'), fullPage: true })
})

for (const admin of [false, true]) test(`${admin ? 'administrator' : 'owner'} sees work blockers before rollout details`, async ({ page }, info) => {
  const state = await setup(page, admin)
  state.view.components[0].ready = false
  state.view.components[0].reason = 'applying'
  state.view.assignments = []
  state.view.components[1].apps!.instances = []
  state.view.components[1].apps!.assignments = []
  state.view.components[1].apps!.instances_total = 0
  state.view.tunnel = { enabled: true, ready: false, reason: 'runtime_pending', cleanup_complete: false }
  state.view.discovery_source = { state: 'excluded', selection_reason: 'unverified', stale: true, failures: 0, publication_blocked: false }
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))

  const summary = page.getByRole('region', { name: 'Work readiness', exact: true })
  await expect(summary.getByRole('heading', { name: 'Not ready to receive work', exact: true })).toBeVisible()
  await expect(summary.getByRole('listitem').filter({ hasText: 'Node deployment' }).first()).toContainText('Resource reconciliation is pending')
  await expect(summary.getByRole('listitem').filter({ hasText: 'Tunnel provisioning' })).toContainText('Waiting for Node deployment to become ready. Provisioning has not been observed.')
  await expect(summary.getByRole('listitem').filter({ hasText: 'Apps' }).first()).toContainText('No apps assigned')
  await expect(summary.getByRole('listitem').filter({ hasText: 'Discovery inventory' })).toContainText('Excluded')
  const row = page.getByRole('row').filter({ hasText: 'worker-status' })
  await expect(row.getByText('Readiness unverified', { exact: true })).toBeVisible()
  await expect(row.getByText('Runtime reporting', { exact: true })).toBeVisible()
  await expect(row.locator('.machine-status.delivered, .status-dot.active')).toHaveCount(0)
  const summaryBox = await summary.boundingBox()
  const artifactBox = await page.getByText('Requested', { exact: true }).boundingBox()
  expect(summaryBox!.y + summaryBox!.height).toBeLessThan(artifactBox!.y)
  await summary.screenshot({ path: info.outputPath('work-readiness.png') })
  if (!admin) {
    await page.setViewportSize({ width: 390, height: 844 })
    await summary.screenshot({ path: info.outputPath('work-readiness-mobile.png') })
    expect(await summary.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true)
  }
  expect(state.writes.filter(path => path !== '/api/bootstrap-token')).toEqual([])
})

test('app readiness requires current healthy and registered assignments and expires with evidence', async ({ page }) => {
  await page.clock.install()
  const state = await setup(page)
  state.view.requested.generation = 1
  const summary = page.getByRole('region', { name: 'Work readiness', exact: true })
  const apps = summary.getByRole('listitem').filter({ hasText: 'Apps' }).first()
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(apps).toContainText('Healthy and registered')
  await expect(summary.getByRole('heading')).toHaveText('Work readiness unverified')
  await expect(summary).toContainText('External app reachability remains unverified.')

  const observed = state.view.components[1].apps!.assignments![0]
  observed.instances = 0; observed.ready = 0; observed.registered = 0
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(apps).toContainText('no app instances loaded')
  await expect(summary.getByRole('heading')).toHaveText('Not ready to receive work')

  observed.instances = 1; observed.ready = 1; observed.registered = 0
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(apps).toContainText('1 healthy and 0 registered')
  observed.registered = 1; observed.activation_generation++
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(apps).toContainText('no fresh observation for the current assignment')

  observed.activation_generation--
  const at = await page.evaluate(() => Date.now())
  state.view.server_time = new Date(at).toISOString()
  observed.probe_expires_at = new Date(at + 3000).toISOString()
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(apps).toContainText('Healthy and registered')
  state.fail = true
  await page.clock.fastForward(4000)
  await expect(apps).toContainText('health or Node registration evidence is missing or expired')
  await expect(apps).not.toContainText('Healthy and registered')
})

test('disabled ingress and discovery do not become blockers, and old reports cannot prove readiness', async ({ page }) => {
  const state = await setup(page)
  state.view.requested.generation = 1
  state.view.tunnel.enabled = false
  state.view.discovery_enabled = false
  state.view.components[0].current = false
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  const summary = page.getByRole('region', { name: 'Work readiness', exact: true })
  await expect(summary.getByRole('heading')).toHaveText('Work readiness unverified')
  await expect(summary.getByRole('listitem').filter({ hasText: 'Node deployment' })).toContainText('earlier rollout')
  await expect(summary.getByText('Disabled', { exact: true })).toHaveCount(2)
  state.view.assignments_omitted = true
  state.view.components[0].current = true
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(summary).toContainText('Additional app assignments were omitted')
  await expect(summary.getByRole('listitem').filter({ hasText: 'Apps' }).first()).not.toContainText('Healthy and registered')
})

test('one failing assignment does not hide healthy apps, and draining stops new work', async ({ page }) => {
  const state = await setup(page)
  state.view.requested.generation = 1
  state.view.assignments.push({ ...state.view.assignments[0], revision_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', name: 'second-app' })
  state.view.components[1].apps!.assignments!.push({ ...state.view.components[1].apps!.assignments![0], revision_id: state.view.assignments[1].revision_id, instances: 0, ready: 0, registered: 0, reason: 'resource_refused' })
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  const summary = page.getByRole('region', { name: 'Work readiness', exact: true })
  await expect(summary.getByRole('heading')).toHaveText('Not fully ready to receive work')
  await expect(summary).toContainText('1 of 2 app assignments')
  await expect(summary).toContainText('second-app: no app instances loaded — Insufficient resources for this assignment')

  state.view.lifecycle = 'draining'
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(summary.getByRole('heading')).toHaveText('Not accepting work')
  await expect(summary).toContainText('draining for removal')
})

test('stale evidence expires when status refresh fails', async ({ page }) => {
  await page.clock.install()
  const state = await setup(page)
  const soon = new Date(Date.now() + 1200).toISOString()
  state.view.components.forEach(c => { c.expires_at = soon })
  state.view.components[1].apps!.instances[0].node_expires_at = soon
  state.view.components[0].delivery_reason = 'fetch_or_publication_failed'
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(page.getByText('Configuration fetch or artifact publication failed', { exact: false })).toBeVisible()
  state.fail = true
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(page.getByText('Status refresh unavailable.', { exact: true })).toBeVisible()
  await page.clock.fastForward(6000)
  await expect(page.getByText('Stale — no fresh report', { exact: true })).toHaveCount(4)
  await page.getByText('Instance evidence and correlation (1)').click()
  await expect(page.getByText('Node work: unknown', { exact: false })).toBeVisible()
})

test('configured probe failure and incomplete cleanup remain separate', async ({ page }) => {
  const state = await setup(page)
  const app = state.view.components[1].apps!, instance = app.instances[0]
  app.instances_omitted = 3; app.instances_total = 4; app.owner_recreated_at = new Date().toISOString()
  app.assignments![0].reason = 'resource_refused'
  instance.probe!.success = false; instance.probe!.failures = 1
  state.view.assignments[0].generation = 3; state.view.assignments[0].activation_generation = 3
  app.assignments![0].generation = 3; app.assignments![0].activation_generation = 3
  app.assignments![0].instances = 0; app.assignments![0].ready = 0; app.assignments![0].registered = 0
  state.view.components[0].apps_error = 'invalid_app_payload'
  instance.withdrawal_id = 'withdrawal-preserved'; instance.deadline = new Date().toISOString(); instance.drain_expired_at = instance.deadline; instance.forced = true; instance.sessions = -1; instance.removal_published_at = instance.deadline; instance.terminated_at = undefined; instance.registration_gone = false; instance.reason = 'cleanup_unconfirmed'
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(page.getByText('3 of 4 instance details omitted', { exact: false })).toBeVisible()
  await expect(page.getByText('Insufficient resources for this assignment', { exact: true })).toBeVisible()
  await expect(page.getByText('App input validation: Downloaded app input is invalid.', { exact: false })).toBeVisible()
  await expect(page.getByText('Node registration was recreated at', { exact: false })).toBeVisible()
  await page.getByText('Instance evidence and correlation (1)').click()
  await expect(page.getByText('1 consecutive failures', { exact: false })).toBeVisible()
  await expect(page.getByText('generation 1 · activation 1 · retained activation', { exact: false })).toBeVisible()
  await expect(page.getByText('actual termination: Unobserved · registration cleanup: unconfirmed', { exact: false })).toBeVisible()
})

test('late status from the previous machine cannot replace the selected machine', async ({ page }) => {
  const state = await setup(page)
  state.hold = true
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect.poll(() => state.held.length).toBe(1)
  state.hold = false
  await page.getByRole('button', { name: 'View status for second-worker' }).click()
  await expect(page.getByRole('heading', { name: 'Runtime status on second-worker' })).toBeVisible()
  await state.held[0].fulfill({ json: { ...state.view, hostname: 'obsolete-machine-evidence' } })
  await expect(page.getByText('obsolete-machine-evidence', { exact: false })).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'Runtime status on worker-status' })).toHaveCount(0)
})

for (const admin of [false, true]) test(`${admin ? 'administrator' : 'owner'} sees clock uncertainty and connector proof expiry independently`, async ({ page }) => {
  await page.clock.install()
  const state = await setup(page, admin, 'clock_uncertain')
  await expect(page.getByRole('row').filter({ hasText: 'worker-status' }).getByText('Clock uncertain', { exact: true })).toBeVisible()
  state.view.components[2].clock_uncertain = true
  state.view.components[2].fresh = false
  const at = Date.parse(state.view.server_time)
  state.view.components[3].connector_expires_at = new Date(at + 10000).toISOString()
  state.view.discovery_selection_expires_at = new Date(at + 20000).toISOString()
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(page.getByRole('region', { name: 'Runtime status for worker-status' }).getByText('Clock uncertain', { exact: true })).toBeVisible()
  await expect(page.getByRole('row').filter({ hasText: 'Tunnel connector' }).getByText('Ready', { exact: true })).toBeVisible()
  await page.getByText('Instance evidence and correlation (1)').click()
  state.fail = true
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(page.getByText('Status refresh unavailable.', { exact: true })).toBeVisible()
  await page.clock.fastForward(11000)
  await expect(page.getByRole('cell', { name: 'No fresh connector readiness observation', exact: true })).toBeVisible()
  await expect(page.getByText('Present in published inventory', { exact: false })).toBeVisible()
  await page.clock.fastForward(10000)
  await expect(page.getByText('Source selection stale', { exact: false })).toHaveCount(2)
  await expect(page.getByText('Present in published inventory', { exact: false })).toHaveCount(0)
  await expect(page.getByText('Stale — no fresh report', { exact: true })).toHaveCount(0)
})

test('a delayed status response cannot renew already expired probe evidence', async ({ page }) => {
  await page.clock.install()
  const state = await setup(page)
  const at = await page.evaluate(() => Date.now())
  state.view.server_time = new Date(at).toISOString()
  const probeExpiry = new Date(at + 5000).toISOString()
  state.view.components[1].apps!.assignments![0].probe_expires_at = probeExpiry
  state.view.components[1].apps!.instances[0].probe!.expires_at = probeExpiry
  state.hold = true
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect.poll(() => state.held.length).toBe(1)
  await page.clock.fastForward(10000)
  await state.held[0].fulfill({ json: state.view })
  await expect(page.getByText('Configured health: Unverified / stale', { exact: false })).toBeVisible()
  await page.getByText('Instance evidence and correlation (1)').click()
  await expect(page.getByText('Probe: stale', { exact: false })).toBeVisible()
  await expect(page.getByText('Stale — no fresh report', { exact: true })).toHaveCount(0)
})

test('fresh failing probe evidence expires on its configured schedule and recovers on a new sample', async ({ page }) => {
  await page.clock.install()
  const state = await setup(page)
  const summary = state.view.components[1].apps!.assignments![0]
  const instance = state.view.components[1].apps!.instances[0]
  const sample = async () => {
    const at = await page.evaluate(() => Date.now())
    state.view.server_time = new Date(at).toISOString()
    summary.ready = 0; instance.ready = false
    instance.probe = { observed_at: new Date(at).toISOString(), due_at: new Date(at + 5000).toISOString(), expires_at: new Date(at + 8000).toISOString(), success: false, failures: 3, started: true }
    summary.probe_expires_at = instance.probe.expires_at
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  }
  await sample()
  await expect(page.getByText('Configured health: 0 ready', { exact: false })).toBeVisible()
  await page.getByText('Instance evidence and correlation (1)').click()
  await expect(page.getByText('Probe: failed', { exact: false })).toBeVisible()
  state.fail = true
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(page.getByText('Status refresh unavailable.', { exact: true })).toBeVisible()
  await page.clock.fastForward(9000)
  await expect(page.getByText('Configured health: Unverified / stale', { exact: false })).toBeVisible()
  await expect(page.getByText('Probe: stale', { exact: false })).toBeVisible()
  state.fail = false
  await sample()
  await expect(page.getByText('Configured health: 0 ready', { exact: false })).toBeVisible()
  await expect(page.getByText('Probe: failed', { exact: false })).toBeVisible()
})

for (const admin of [false, true]) test(`${admin ? 'administrator' : 'owner'} can inspect the original retired enrollment without app mutations`, async ({ page }) => {
  const state = await setup(page, admin, 'stale', true)
  await expect.poll(() => state.statusNodes[0]).toBe(node)
  await expect(page.getByText('Desired removal', { exact: false })).toBeVisible()
  if (admin) await expect(page.getByRole('button', { name: 'Manage apps for worker-status' })).toHaveText('Inspect cleanup')
  else await expect(page.getByText('Cleanup pending', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Assign selected revision', exact: true })).toHaveCount(0)
})

test('onchain readiness stays separate from remote handoff', async ({ page }) => {
  await page.clock.install()
  const state = await setup(page, false)
  state.view.onchain = { desired: { mode: 'onchain', generation: 3, recipient: `0x${'2'.repeat(40)}`, network: 'custom' }, delivered_generation: 3 }
  state.view.components[0].onchain = { generation: 3, mode: 'onchain', applied: true, ready: true, handoff: 'degraded' }
  await page.clock.fastForward(5100)
  await expect(page.getByRole('region', { name: 'Onchain operation' })).toContainText('Local onchain admission: ready')
  await expect(page.getByRole('region', { name: 'Onchain operation' })).toContainText('Remote handoff: degraded')

})
