import { useEffect, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { CircleAlert, CircleCheck, CircleHelp, Minus } from 'lucide-react'
import { api, APIError } from './api'

type Stage = { generation: number; apps_digest?: string; artifact_digest?: string }
type Probe = { observed_at: string; due_at: string; expires_at: string; success: boolean; failures: number; started: boolean }
type Instance = { revision_id: string; generation: number; activation_generation: number; instance_id: string; pod_uid?: string; runner_id?: string; app_id?: string; phase: string; ready: boolean; registered: boolean; capacity: number; sessions: number; reason?: string; workload_reason?: string; deadline?: string; withdrawal_id?: string; drain_expired_at?: string; forced?: boolean; removal_published_at?: string; terminated_at?: string; registration_gone?: boolean; node_observed_at?: string; node_expires_at?: string; accepted_sequence?: number; startup_deadline?: string; probe?: Probe }
type AssignmentObservation = { revision_id: string; generation: number; activation_generation: number; reason?: string; instances: number; ready: number; registered: number; cleanup_pending: number; node_expires_at?: string; probe_expires_at?: string }
type Apps = { managed_secrets?: boolean; secrets_identity_ready?: boolean; secrets_encryption_ready?: boolean; secrets_protocol?: number; secret_rollouts?: Record<string,{generation:number;desired:string;applied?:string;reason?:string}>; desired_generation: number; desired_digest?: string; staged?: Stage; published?: Stage; applied?: Stage; reason?: string; instances: Instance[]; assignments?: AssignmentObservation[]; instances_total?: number; instances_omitted?: number; owner_recreated_at?: string }
type OnchainEvidence = { generation: number; mode: string; applied: boolean; ready: boolean; handoff: string }
type Component = { onchain?: OnchainEvidence; observer_id?: string; observer_started_at?: string; component: string; generation: number; observed_at?: string; received_at?: string; expires_at?: string; fresh: boolean; current: boolean; ready: boolean; reason: string; clock_uncertain: boolean; bundle_sha256?: string; downloaded?: Stage; downloaded_at?: string; delivery_reason?: string; apps_error?: string; apps?: Apps; connector_observed_at?: string; connector_expires_at?: string }
type Assignment = { revision_id: string; digest: string; name: string; version: string; revision: number; generation: number; activation_generation: number; desired: string; replicas: number; start_allowed: boolean; completed_at: string | null; failure?: string; health: { type: string; interval: string; timeout: string; failure_threshold: number } }
type Membership = { state: string; queried_at?: string; observed_at?: string; expires_at?: string }
export type MachineObservation = { onchain?: { desired: { mode: string; generation: number; network?: string; chain_id?: number; recipient?: string; controller?: string; wei_per_usd?: string; eth_usd_feed?: string; ticket_face_value?: string; ticket_win_prob?: string }; delivered_generation: number }; node_id: string; hostname: string; lifecycle: string; rollout_generation: number; requested: Stage; delivered?: Stage; delivered_at?: string; delivery_reason?: string; assignments: Assignment[]; assignments_omitted: boolean; components: Component[]; tunnel: { enabled: boolean; ready: boolean; reason: string; verified_at?: string; expires_at?: string; cleanup_complete: boolean }; discovery_enabled: boolean; discovery_initialized: boolean; discovery_selection_stale: boolean; discovery_selection_expires_at?: string; discovery_source?: { state: string; selection_reason: string; stale: boolean; expires_at?: string; failures: number; transport_outcome?: string; last_attempt?: string; last_success?: string; publication_blocked: boolean }; membership: Record<string, Membership>; external_reachability: string; server_time: string }

export function machineStatusSummary(machine: { terminal?: boolean; lifecycle?: string; report_state?: string; last_config_fetch_at?: string | null }) {
  const labels: Record<string, string> = { observed: 'Runtime reporting', stale: 'Status stale', clock_uncertain: 'Clock uncertain' }
  return machine.terminal ? 'Cleanup pending' : labels[machine.report_state || ''] || (machine.last_config_fetch_at ? 'Config requested' : 'Enrolled')
}

export function MachineReadinessBadge({ machine }: { machine: Parameters<typeof machineStatusSummary>[0] }) {
  return <div className="machine-readiness"><span className="machine-status stale"><span className="status-dot" />{machine.terminal || machine.lifecycle === 'draining' ? 'Not accepting work' : 'Readiness unverified'}</span><span className="machine-report-state">{machineStatusSummary(machine)}</span></div>
}

const reasons: Record<string, string> = {
  runtime_pending: 'Waiting for Node deployment to become ready',
  onchain_not_ready: 'Onchain Node is not ready; inspect credential delivery, retained onchain state, RPC and rate source', sandbox_pending: 'Sandbox or Pod network setup is pending', invalid_app_payload: 'Downloaded app input is invalid',
  onchain_pending: 'Waiting for the target onchain configuration', onchain_incompatible: 'App price is incompatible with the target onchain mode', resource_refused: 'Insufficient resources for this assignment', cleanup_prerequisite: 'Waiting for previous revision cleanup', cleanup_pending: 'Waiting for earlier instance cleanup', generation_failed: 'App configuration could not be rendered', invalid_definition: 'App definition is invalid', unsupported_instance_mode: 'Instance lifetime is not supported', unsupported_stop_signal: 'Configured stop signal is not supported', image_pull_failed: 'Container image could not be pulled', container_start_failed: 'Container could not start', startup_failed: 'Startup deadline expired', readiness_failed: 'Configured readiness check failed', memory_limit: 'Container exceeded its memory limit', scheduling_refused: 'Kubernetes refused scheduling', isolation_failed: 'Sandbox isolation could not start', state_recovery_failed: 'App Reconciler state recovery failed; management repair remains available', registration_reset: 'Node registration was lost or expired', node_registration_recreated: 'Node registration was recreated; previous work is unconfirmed', clock_uncertain: 'Observation clock is uncertain', process_lost: 'App process disappeared', process_failed: 'App process failed', observation_pending: 'App state could not be observed', fetch_or_publication_failed: 'Configuration fetch or artifact publication failed', access_denied: 'Discovery Access authentication was denied', credential_unavailable: 'Discovery credential is unavailable', unreported: 'No observation received', input_regression: 'Older app input was refused', registration_failed: 'Node registration failed', registration_pending: 'Node registration is pending', node_unavailable: 'Node registration service is unreachable', node_request_failed: 'Node rejected the registration request', heartbeat_response: 'Node registration response is invalid', heartbeat_ttl: 'Node registration expiry is invalid', registration_auth_failed: 'Node rejected registration credentials', tls_pending: 'Waiting for TLS', drain_pending: 'Drain or cleanup is pending', runtime_offline: 'Runtime has no fresh report', reconcile_failed: 'Flux resource reconciliation failed', cleanup_failed: 'Resource cleanup failed', ownership_conflict: 'Tunnel resource ownership conflicts', provisioning_pending: 'Tunnel provisioning is pending', denied_destination: 'Discovery destination was refused', dns: 'Discovery DNS lookup failed', timeout: 'Discovery collection timed out', http_error: 'Discovery source returned an error', redirect: 'Discovery source redirected the request', transport_error: 'Discovery source could not be reached', unsupported_stop_signal_field: 'Host does not support the requested stop signal', stop_signal_unverified: 'The configured stop signal could not be verified; admission is withheld', process_failed_to_start: 'App process failed to start', registration_cleanup_failed: 'Registration cleanup failed', clock_state_unavailable: 'Clock state is unavailable', app_cleanup_pending: 'App cleanup remains pending', drain_timeout: 'Drain deadline expired', input_unavailable: 'App input is unavailable', publication_failed: 'App artifact publication failed', serving_failed: 'App artifact serving failed', failed: 'Component reported failure', offline: 'Component has no ready observation', connector_observation_stale: 'No fresh connector readiness observation', applying: 'Resource reconciliation is pending', ready: 'Ready', removed: 'Removed', rollout_pending: 'Waiting for the new configuration to apply', cleanup_unconfirmed: 'Cleanup is unconfirmed',
}
function reason(code?: string) { return code ? reasons[code] || code.replaceAll('_', ' ') : '' }
function date(value?: string | null) { return value && Date.parse(value) > 0 ? new Date(value).toLocaleString() : 'Unobserved' }
function alive(value: string | undefined, now: number) { return !!value && Date.parse(value) > now }

type ReadinessCheck = { label: string; state: 'ready' | 'blocked' | 'unverified' | 'disabled'; status: string; detail: string }

function WorkReadiness({ view, clock }: { view: MachineObservation; clock: number }) {
  const fresh = (c?: Component) => !!c && !!c.received_at && c.fresh && !c.clock_uncertain && alive(c.expires_at, clock)
  const runtime = view.components.find(c => c.component === 'runtime')
  const runner = view.components.find(c => c.component === 'runner')
  const connector = view.components.find(c => c.component === 'connector')
  const diagnosis = view.components.find(c => c.component === 'app-reconciler')
  const checks: ReadinessCheck[] = []
  function componentCheck(label: string, c?: Component): ReadinessCheck {
    if (!c?.received_at) return { label, state: 'unverified', status: 'Unobserved', detail: 'No status report has been received.' }
    if (c.clock_uncertain) return { label, state: 'unverified', status: 'Clock uncertain', detail: 'Observation timing cannot be trusted.' }
    if (!fresh(c)) return { label, state: 'unverified', status: 'Status stale', detail: 'No fresh report. Current readiness cannot be confirmed.' }
    if (!c.current) return { label, state: 'unverified', status: 'Rollout pending', detail: 'The latest report describes an earlier rollout.' }
    return c.ready ? { label, state: 'ready', status: 'Ready', detail: 'Confirmed by a fresh report for the current rollout.' }
      : { label, state: 'blocked', status: c.reason === 'applying' ? 'Pending' : 'Not ready', detail: reason(c.reason) || 'The component has not reported ready.' }
  }
  checks.push(componentCheck('Node deployment', runtime))

  if (view.onchain?.desired.mode === 'onchain') {
    const o = runtime?.onchain
    const ready = fresh(runtime) && runtime?.current && o?.mode === 'onchain' && o.applied && o.ready && o.generation === view.onchain.desired.generation
    checks.push({ label: 'Onchain admission', state: ready ? 'ready' : 'unverified', status: ready ? 'Ready' : 'Unverified', detail: ready ? 'The requested onchain configuration is applied and local admission is ready.' : 'Local onchain admission has not been confirmed for the requested configuration.' })
  }

  const active = view.assignments.filter(a => a.desired === 'present' && a.replicas > 0)
  let readyApps = 0
  const appProblems: { state: 'blocked' | 'unverified'; detail: string }[] = []
  for (const a of active) {
    const observed = runner?.apps?.assignments?.find(o => o.revision_id === a.revision_id && o.activation_generation === a.activation_generation && o.generation === a.generation)
    if (!a.start_allowed) appProblems.push({ state: 'blocked', detail: `${a.name}: startup is not permitted for this assignment.` })
    else if (a.failure) appProblems.push({ state: 'blocked', detail: `${a.name}: ${reason(a.failure)}.` })
    else if (!fresh(runner) || !runner?.current || !observed) appProblems.push({ state: 'unverified', detail: `${a.name}: no fresh observation for the current assignment.` })
    else if (observed.instances === 0) appProblems.push({ state: 'blocked', detail: `${a.name}: no app instances loaded${observed.reason ? ` — ${reason(observed.reason)}` : ''}.` })
    else if (!alive(observed.probe_expires_at, clock) || !alive(observed.node_expires_at, clock)) appProblems.push({ state: 'unverified', detail: `${a.name}: health or Node registration evidence is missing or expired.` })
    else if (observed.ready < a.replicas || observed.registered < a.replicas) appProblems.push({ state: 'blocked', detail: `${a.name}: ${observed.ready} healthy and ${observed.registered} registered of ${a.replicas} requested instances${observed.reason ? ` — ${reason(observed.reason)}` : ''}.` })
    else if (observed.ready + observed.registered - observed.instances < a.replicas) appProblems.push({ state: 'unverified', detail: `${a.name}: healthy and registered counts do not confirm the same instances.` })
    else readyApps++
  }
  if (view.assignments_omitted) appProblems.push({ state: 'unverified', detail: 'Additional app assignments were omitted from this report.' })
  if (active.length && runner?.apps?.applied?.generation !== view.requested.generation) appProblems.push({ state: 'unverified', detail: 'The requested app configuration has not been confirmed applied.' })
  const appError = fresh(runtime) && runtime?.current && runtime.apps_error || fresh(runner) && runner?.current && (runner.apps?.reason || (!runner.ready && runner.reason)) || fresh(diagnosis) && diagnosis?.current && !diagnosis.ready && (diagnosis.apps?.reason || diagnosis.reason)
  if (appError) {
    appProblems.push({ state: 'blocked', detail: reason(appError) })
  }
  const appState = appProblems.some(p => p.state === 'blocked') ? 'blocked' : appProblems.length ? 'unverified' : 'ready'
  checks.push(active.length === 0 && !view.assignments_omitted
    ? { label: 'Apps', state: 'blocked', status: 'No apps assigned', detail: 'No active app assignments. There are no apps configured to receive new work.' }
    : { label: 'Apps', state: appState, status: appState === 'ready' ? 'Healthy and registered' : appState === 'blocked' ? 'Apps not ready' : 'Unverified', detail: `${readyApps} of ${active.length} app assignments have all requested instances healthy and registered.${appProblems.length ? ` ${appProblems[0].detail}` : ''}` })

  const tunnel = view.tunnel
  const tunnelReady = tunnel.ready && alive(tunnel.expires_at, clock)
  let tunnelCheck: ReadinessCheck = { label: 'Tunnel provisioning', state: 'ready', status: 'Verified', detail: 'Provisioning has a fresh verification.' }
  if (!tunnel.enabled) tunnelCheck = { ...tunnelCheck, state: 'disabled', status: 'Disabled', detail: 'No managed tunnel is configured.' }
  else if (!tunnelReady) tunnelCheck = { ...tunnelCheck, state: tunnel.reason && tunnel.reason !== 'ready' ? 'blocked' : 'unverified', status: tunnel.reason === 'runtime_pending' ? 'Waiting for Node deployment' : 'Unverified', detail: `${reason(tunnel.reason === 'ready' ? '' : tunnel.reason) || 'No fresh provisioning verification'}. ${date(tunnel.verified_at) === 'Unobserved' ? 'Provisioning has not been observed.' : 'Provisioning readiness is not currently verified.'}` }
  if (tunnel.enabled && tunnelReady) {
    const c = componentCheck('Tunnel connector', connector)
    if (c.state !== 'ready' || !alive(connector?.connector_expires_at, clock)) tunnelCheck = { ...tunnelCheck, state: c.state === 'blocked' ? 'blocked' : 'unverified', status: 'Connector not verified', detail: c.state !== 'ready' ? c.detail : reason('connector_observation_stale') }
  }
  checks.push(tunnelCheck)

  const source = view.discovery_source
  let discovery: ReadinessCheck = { label: 'Discovery inventory', state: 'ready', status: 'Current', detail: 'The node is included in a fresh discovery collection.' }
  if (!view.discovery_enabled) discovery = { ...discovery, state: 'disabled', status: 'Disabled', detail: 'Fleet discovery collection is disabled.' }
  else if (!view.discovery_initialized) discovery = { ...discovery, state: 'unverified', status: 'Unobserved', detail: 'Discovery has not collected an inventory, or its cache was lost.' }
  else if (view.discovery_selection_stale || !alive(view.discovery_selection_expires_at, clock)) discovery = { ...discovery, state: 'unverified', status: 'Selection stale', detail: 'The current discovery source selection cannot be confirmed.' }
  else if (!source || source.state === 'excluded') discovery = { ...discovery, state: 'blocked', status: 'Excluded', detail: `This node is excluded from fleet discovery${source?.selection_reason && source.selection_reason !== 'selected' ? ` (${reason(source.selection_reason)})` : ''}. Its apps are not being advertised for work.` }
  else if (source.stale || !alive(source.expires_at, clock)) discovery = { ...discovery, state: 'unverified', status: 'Inventory stale', detail: `No fresh discovery inventory${source.transport_outcome ? ` — ${reason(source.transport_outcome)}` : ''}.` }
  else if (source.publication_blocked) discovery = { ...discovery, state: 'blocked', status: 'Publication blocked', detail: 'Some app records were blocked from the published inventory.' }
  else if (active.length && !runner?.apps?.instances.some(i => active.some(a => a.revision_id === i.revision_id && a.generation === i.generation && a.activation_generation === i.activation_generation) && view.membership[i.instance_id]?.state === 'present' && alive(view.membership[i.instance_id]?.expires_at, clock))) discovery = { ...discovery, state: 'unverified', status: 'Apps unverified', detail: 'No current app instance is confirmed in the published inventory.' }
  checks.push(discovery)

  const retired = view.lifecycle === 'cleanup_pending' || view.lifecycle === 'removed'
  const draining = view.lifecycle === 'draining'
  const blocked = checks.some(c => c.state === 'blocked')
  const partiallyReady = readyApps > 0 && checks.every(c => c.label === 'Apps' || c.state !== 'blocked')
  const title = retired || draining ? 'Not accepting work' : blocked ? partiallyReady ? 'Not fully ready to receive work' : 'Not ready to receive work' : 'Work readiness unverified'
  const HeadingIcon = retired || draining || blocked ? CircleAlert : CircleHelp
  return <section className="work-readiness" aria-label="Work readiness">
    <div className="readiness-heading"><HeadingIcon size={23} aria-hidden="true" /><div><h4>{title}</h4><p>{retired ? 'This enrollment is retired. Cleanup evidence is shown below.' : draining ? 'This node is draining for removal and is not accepting new work.' : blocked ? 'The following checks explain what is preventing or limiting work.' : 'External app reachability has not been verified. Review the available checks below.'}</p></div></div>
    <ul className="readiness-checks">{checks.map(check => {
      const Icon = check.state === 'ready' ? CircleCheck : check.state === 'blocked' ? CircleAlert : check.state === 'disabled' ? Minus : CircleHelp
      return <li className={`readiness-check ${check.state}`} key={check.label}><Icon size={18} aria-hidden="true" /><div><div className="readiness-check-heading"><strong>{check.label}</strong><span>{check.status}</span></div><p>{check.detail}</p></div></li>
    })}</ul>
    <p className="readiness-note">Runtime reporting and downloaded configuration do not establish work readiness. External app reachability remains unverified.</p>
  </section>
}

function Identity({ value, label }: { value?: Stage; label: string }) {
  return <div className="status-identity"><strong>{label}</strong><span>{value ? `App generation ${value.generation || 'unknown'}` : 'Unobserved'}</span>{value?.apps_digest && <code title="Canonical app intent digest">{value.apps_digest}</code>}{value?.artifact_digest && <code title="Artifact digest">{value.artifact_digest}</code>}</div>
}

export function MachineStatus({ session, machine, authorityFailure }: { session: Session; machine: { node_id: string; hostname: string }; authorityFailure?: (error: APIError) => void }) {
  const [view, setView] = useState<MachineObservation | null>(null)
  const [problem, setProblem] = useState('')
  const [now, setNow] = useState(Date.now())
  const [offset, setOffset] = useState(0)
  useEffect(() => {
    let current = true, pending = false
    const controller = new AbortController()
    setView(null); setProblem('')
    const load = async () => {
      if (!current || pending || document.hidden) return
      pending = true
      const started = performance.now()
      try {
        const data = await api<MachineObservation>(session, `/api/machines/${encodeURIComponent(machine.node_id)}/status`, { signal: controller.signal })
        if (!current || controller.signal.aborted) return
        if (data.node_id !== machine.node_id) { setView(null); setProblem('Machine enrollment changed. Select the machine again.'); return }
        const arrived = Date.now()
        setOffset(Date.parse(data.server_time) + performance.now() - started - arrived)
        setNow(arrived); setView(data); setProblem('')
      } catch (error) {
        if (!current || controller.signal.aborted) return
        if (error instanceof APIError && [401, 403, 404].includes(error.status)) { setView(null); if (error.status !== 404) authorityFailure?.(error) }
        setProblem(error instanceof Error ? error.message : 'Status could not be refreshed. Last observations continue to expire.')
      } finally { pending = false }
    }
    void load()
    const poll = window.setInterval(load, 5000), tick = window.setInterval(() => setNow(Date.now()), 1000)
    document.addEventListener('visibilitychange', load)
    return () => { current = false; controller.abort(); window.clearInterval(poll); window.clearInterval(tick); document.removeEventListener('visibilitychange', load) }
    // The caller keys this panel by account and enrollment.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.user.id, session.access_token, machine.node_id])
  const clock = now + offset
  const fresh = (c?: Component) => !!c && c.fresh && alive(c.expires_at, clock)
  const runner = view?.components.find(c => c.component === 'runner'), apps = runner?.apps
  const runtime = view?.components.find(c => c.component === 'runtime')
  const diagnosis = view?.components.find(c => c.component === 'app-reconciler')
  const status = (c: Component) => !c.received_at ? 'Unreported' : c.clock_uncertain ? 'Clock uncertain' : !fresh(c) ? 'Stale — no fresh report' : !c.current ? 'Earlier rollout' : c.component === 'connector' && !alive(c.connector_expires_at, clock) ? reason('connector_observation_stale') : c.ready ? c.component === 'runner' ? 'Reporting — see assignment evidence' : 'Ready' : reason(c.reason) || 'Pending'
  function discovered(i: Instance) {
    const m = view?.membership[i.instance_id]
    if (!view?.discovery_enabled) return 'Disabled'
    if (!m) return 'Unverified'
    if (view.discovery_selection_stale || !alive(view.discovery_selection_expires_at, clock)) return 'Source selection stale'
    if (m.state === 'present' && alive(m.expires_at, clock)) return 'Present in published inventory'
    if (m.expires_at && !alive(m.expires_at, clock)) return 'Stale inventory'
    return m.state === 'absent' ? 'Absent from last successful inventory' : reason(m.state)
  }
  return <section className="machine-observation" aria-label={`Runtime status for ${machine.hostname}`}>
    <div className="section-heading"><div><h3>Runtime status on {machine.hostname}</h3><code>{machine.node_id}</code></div></div>
    {problem && <div className="notice error" role="alert">{problem}</div>}
    {!view && !problem && <p role="status">Loading observed state…</p>}
    {view && <>
      <WorkReadiness view={view} clock={clock} />
      {view.onchain && <section aria-label="Onchain operation">
        <h4>Onchain operation</h4>
        <p>Desired: {view.onchain.desired.mode} · generation {view.onchain.desired.generation}. Delivered generation: {view.onchain.delivered_generation}.</p>
        {view.onchain.desired.recipient && <p>Configured onchain orchestrator: <code>{view.onchain.desired.recipient}</code> · {view.onchain.desired.network}</p>}
        <p>Configuration: {fresh(runtime) && runtime?.onchain?.applied ? `applied generation ${runtime.onchain.generation}` : 'pending or unobserved'}. Local onchain admission: {fresh(runtime) && runtime?.onchain?.mode === 'onchain' && runtime.onchain.ready ? 'ready' : 'not verified'}. Remote handoff: {fresh(runtime) ? runtime?.onchain?.handoff || 'unverified' : 'unverified'}.</p>
        {fresh(runtime) && runtime?.onchain?.mode === 'offchain' && <p>Effective service is free; catalog registration quotes are retained.</p>}
      </section>}

      <p className="muted">{reason(view.lifecycle)} · rollout generation {view.rollout_generation}. External app reachability: unverified. Configured checks observe the private app endpoint.</p>
      {view.delivery_reason && <div className="notice error" role="alert">{reason(view.delivery_reason)}. Retained app input keeps its original identity.</div>}
      {runtime?.apps_error && <div className="notice error" role="alert">App input validation: {reason(runtime.apps_error)}. Management status is reported separately.</div>}
      {diagnosis && fresh(diagnosis) && !diagnosis.ready && <div className="notice error" role="alert">{reason(diagnosis.apps?.reason || diagnosis.reason)}</div>}
      <div className="status-identities"><Identity label="Requested" value={view.requested} /><Identity label="Delivered bundle" value={view.delivered} /><Identity label="Downloaded and validated" value={runtime?.downloaded} /><Identity label="Staged app artifact" value={apps?.staged} /><Identity label="Published app artifact" value={apps?.published} /><Identity label="Applied app artifact" value={apps?.applied} /></div>
      <p className="muted">Bundle published: {date(view.delivered_at)} · validated download: {date(runtime?.downloaded_at)}{runtime?.delivery_reason ? ` · ${reason(runtime.delivery_reason)}` : ''}</p>
      <div className="table-scroll"><table><thead><tr><th>COMPONENT</th><th>OBSERVED STATE</th><th>OBSERVED / RECEIVED</th></tr></thead><tbody>{view.components.map(c => <tr key={c.component}><td>{c.component === 'runtime' ? 'Management / Node deployment' : c.component === 'app-reconciler' ? 'App Reconciler diagnostics' : c.component === 'runner' ? 'App lifecycle / registration' : 'Tunnel connector'}</td><td>{status(c)}{c.apps?.reason && <p>{reason(c.apps.reason)}</p>}</td><td>{date(c.observed_at)}<br /><span className="muted">Received {date(c.received_at)}</span>{c.observer_id && <p className="muted">Reporter <code>{c.observer_id}</code><br />Started {date(c.observer_started_at)}</p>}</td></tr>)}</tbody></table></div>
      <div className="status-path"><p><strong>Tunnel provisioning:</strong> {!view.tunnel.enabled ? 'Disabled' : view.tunnel.ready && alive(view.tunnel.expires_at, clock) ? 'Verified' : reason(view.tunnel.reason) || 'Unverified'} · {date(view.tunnel.verified_at)}</p><p><strong>Discovery collection:</strong> {!view.discovery_enabled ? 'Disabled' : !view.discovery_initialized ? 'Uninitialized / cache lost' : view.discovery_selection_stale || !alive(view.discovery_selection_expires_at, clock) ? 'Source selection stale' : view.discovery_source ? `${view.discovery_source.state}${view.discovery_source.stale || !alive(view.discovery_source.expires_at, clock) ? ' · stale' : ''} · ${reason(view.discovery_source.transport_outcome)} · last success ${date(view.discovery_source.last_success)}` : 'Source excluded'}{view.discovery_source?.publication_blocked ? ' · Some records were blocked from publication' : ''}</p></div>
      <p><strong>Secret delivery:</strong> {!fresh(runner)?'Status unverified':apps?.secrets_protocol!==1?'Runtime capability unverified':!apps.managed_secrets?'Activation pending':`Managed · identity ${apps.secrets_identity_ready?'ready':'pending'} · cluster encryption ${apps.secrets_encryption_ready?'verified':'pending'}`}.</p>
      {apps?.secret_rollouts && Object.keys(apps.secret_rollouts).length>0 && <section aria-label="Secret rollout status"><h3>Secret rollouts</h3><div className="table-scroll"><table><thead><tr><th>APP REVISION</th><th>ROLLOUT</th><th>STATE</th></tr></thead><tbody>{Object.entries(apps.secret_rollouts).map(([id,r])=><tr key={id}><td>{view.assignments.find(a=>a.revision_id===id)?.name||id}</td><td>{r.generation}</td><td>{!fresh(runner)?'Status stale':r.reason?reason(r.reason):r.applied===r.desired?'Applied — ready and registered':'Pending rotation'}</td></tr>)}</tbody></table></div></section>}
      {(apps?.instances_omitted || view.assignments_omitted) ? <div className="notice error" role="status">Diagnostics are incomplete: {apps?.instances_omitted || 0} of {apps?.instances_total || 0} instance details omitted{view.assignments_omitted ? '; additional assignment records omitted' : ''}. Counts below describe the full reported assignment, not just visible instances.</div> : null}
      {apps?.owner_recreated_at && Date.parse(apps.owner_recreated_at) > 0 && <p role="status">Node registration was recreated at {date(apps.owner_recreated_at)}. This does not confirm survival of earlier sessions.</p>}
      {view.assignments.map(a => {
        const observed = apps?.assignments?.find(o => o.revision_id === a.revision_id && o.activation_generation === a.activation_generation)
        const current = fresh(runner) && runner?.current && observed?.generation === a.generation
        const instances = apps?.instances.filter(i => i.revision_id === a.revision_id) || []
        return <article className="observed-assignment" key={a.revision_id} aria-label={`Observed ${a.name} revision ${a.revision}`}>
          <h4>{a.name} / revision {a.revision} <span className="muted">{a.version}</span></h4>
          <p>Desired {a.desired === 'absent' ? 'removal' : `${a.replicas} replicas`} · generation {a.generation} · activation {a.activation_generation}. Observed generation {observed?.generation || 'unknown'}.</p>
          <p><strong>Applied:</strong> {a.completed_at ? a.desired === 'absent' ? 'Removed — cleanup confirmed' : 'Resource reconciliation confirmed' : a.failure ? reason(a.failure) : 'Pending resource reconciliation'} · <strong>Configured health:</strong> {current && alive(observed?.probe_expires_at, clock) ? `${observed?.ready || 0} ready` : 'Unverified / stale'} · <strong>Registered:</strong> {current && alive(observed?.node_expires_at, clock) ? `${observed?.registered || 0} confirmed` : 'Unverified / stale'}</p>
          <p className="muted">{a.health.type.toUpperCase()} readiness · every {a.health.interval} · timeout {a.health.timeout} · {a.health.failure_threshold} failures to withdraw readiness</p>
          {(a.failure || observed?.reason) && <p className="notice error" role="alert">{reason(a.failure || observed?.reason)}</p>}
          {!!observed?.cleanup_pending && <p role="status">{observed.cleanup_pending} instance cleanup operations remain pending.</p>}
          <details><summary>Instance evidence and correlation ({instances.length})</summary>{instances.length === 0 && <p>No instance observation. Startup may not have been permitted.</p>}{instances.map(i => <div className="instance-evidence" key={i.instance_id}>
            <code>Instance {i.instance_id} · generation {i.generation} · activation {i.activation_generation}{i.activation_generation !== a.activation_generation ? ' · retained activation' : ''} · Pod {i.pod_uid || 'unobserved'} · runner {i.runner_id || 'unconfirmed'} · app {i.app_id || 'unconfirmed'}</code>
            <p>{reason(i.phase)}{i.reason ? ` · ${reason(i.reason)}` : ''}{i.workload_reason ? ` · ${reason(i.workload_reason)}` : ''}. Configured capacity {i.capacity}; Node work: {i.registration_gone ? 'registration cleanup confirmed' : !fresh(runner) || !alive(i.node_expires_at, clock) || i.sessions < 0 ? 'unknown' : `${i.sessions} sessions`}.</p>
            <p>Probe: {i.probe ? `${alive(i.probe.expires_at, clock) && fresh(runner) ? i.probe.success ? 'passed' : 'failed' : 'stale'} · ${i.probe.failures} consecutive failures · ${date(i.probe.observed_at)}` : 'unobserved'} · startup deadline {date(i.startup_deadline)}</p>
            <p>Discovery: {discovered(i)} · snapshot {date(view.membership[i.instance_id]?.queried_at)}</p>
            {i.withdrawal_id && <p>Withdrawal {i.withdrawal_id} · drain deadline {date(i.deadline)} · expired {date(i.drain_expired_at)}</p>}
            {(i.withdrawal_id || i.forced) && <p>Removal published: {date(i.removal_published_at)} · actual termination: {date(i.terminated_at)} · registration cleanup: {i.registration_gone ? 'confirmed' : 'unconfirmed'}</p>}
          </div>)}</details>
        </article>
      })}
      {view.assignments.length === 0 && <p>No active or unfinished app assignments.</p>}
      <p className="muted">Use the enrollment, revision, instance, Pod, runner and app identifiers above to correlate existing Runtime, Flux and Node logs. Session identifiers stay in authorized logs and events.</p>
    </>}
  </section>
}
