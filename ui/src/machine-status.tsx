import { useEffect, useState } from 'react'
import type { Session } from '@supabase/supabase-js'
import { CircleAlert, CircleCheck, CircleHelp, Minus } from 'lucide-react'
import { api, APIError } from './api'
import { appEvidenceAt, classifyReadiness, nextReadinessExpiry, observationState, type ReadinessSnapshot } from './readiness'

type Stage = { generation: number; apps_digest?: string; artifact_digest?: string }
type Probe = { observed_at: string; due_at: string; expires_at: string; success: boolean; failures: number; started: boolean }
type Instance = { revision_id: string; generation: number; activation_generation: number; instance_id: string; pod_uid?: string; runner_id?: string; app_id?: string; phase: string; ready: boolean; registered: boolean; capacity: number; sessions: number; reason?: string; workload_reason?: string; deadline?: string; withdrawal_id?: string; drain_expired_at?: string; forced?: boolean; removal_published_at?: string; terminated_at?: string; registration_gone?: boolean; node_observed_at?: string; node_expires_at?: string; accepted_sequence?: number; startup_deadline?: string; probe?: Probe }
type AssignmentObservation = { revision_id: string; generation: number; activation_generation: number; reason?: string; instances: number; ready: number; registered: number; cleanup_pending: number; node_expires_at?: string; probe_expires_at?: string }
type Apps = { managed_secrets?: boolean; secrets_identity_ready?: boolean; secrets_encryption_ready?: boolean; secrets_protocol?: number; secret_rollouts?: Record<string,{generation:number;desired:string;applied?:string;reason?:string}>; desired_generation: number; desired_digest?: string; staged?: Stage; published?: Stage; applied?: Stage; reason?: string; instances: Instance[]; assignments?: AssignmentObservation[]; instances_total?: number; instances_omitted?: number; owner_recreated_at?: string }
type OnchainEvidence = { generation: number; mode: string; applied: boolean; ready: boolean; handoff: string }
type Component = { onchain?: OnchainEvidence; observer_id?: string; observer_started_at?: string; component: string; generation: number; observed_at?: string; received_at?: string; expires_at?: string; fresh: boolean; current: boolean; ready: boolean; reason: string; clock_uncertain: boolean; bundle_sha256?: string; downloaded?: Stage; downloaded_at?: string; delivery_reason?: string; apps_error?: string; apps?: Apps; connector_observed_at?: string; connector_expires_at?: string }
type Assignment = { revision_id: string; digest: string; name: string; version: string; revision: number; generation: number; activation_generation: number; desired: string; replicas: number; start_allowed: boolean; completed_at: string | null; failure?: string; health: { type: string; interval: string; timeout: string; failure_threshold: number } }
type Membership = { state: string; queried_at?: string; observed_at?: string; expires_at?: string }
export type MachineObservation = ReadinessSnapshot & { onchain?: { desired: { mode: string; generation: number; network?: string; chain_id?: number; recipient?: string; controller?: string; wei_per_usd?: string; eth_usd_feed?: string; ticket_face_value?: string; ticket_win_prob?: string }; delivered_generation: number }; node_id: string; hostname: string; lifecycle: string; rollout_generation: number; requested: Stage; delivered?: Stage; delivered_at?: string; delivery_reason?: string; assignments: Assignment[]; assignments_omitted: boolean; components: Component[]; tunnel: { enabled: boolean; ready: boolean; reason: string; verified_at?: string; expires_at?: string; cleanup_complete: boolean }; discovery_enabled: boolean; discovery_initialized: boolean; discovery_selection_stale: boolean; discovery_selection_expires_at?: string; discovery_source?: { state: string; selection_reason: string; stale: boolean; expires_at?: string; failures: number; transport_outcome?: string; last_attempt?: string; last_success?: string; publication_blocked: boolean }; membership: Record<string, Membership>; external_reachability: string; server_time: string }

const readinessLabels = {
  ready: 'Ready to receive work',
  pending: 'Readiness pending',
  partial: 'Partially ready to receive work',
  unverified: 'Readiness unverified',
  blocked: 'Not ready to receive work',
  inactive: 'Not accepting work',
}
export type MachineReadinessSummary = ReadinessSnapshot & { report_state?: string; last_config_fetch_at?: string | null }

function useReadiness(snapshot: ReadinessSnapshot) {
  const { readiness_evidence: evidence, readinessRequestedAt: started } = snapshot
  const [, setTick] = useState(0)
  useEffect(() => {
    if (!evidence || started === undefined) return
    let timer: number | undefined
    const schedule = () => {
      const age = performance.now() - started
      const next = nextReadinessExpiry(evidence, age)
      if (Number.isFinite(next)) {
        timer = window.setTimeout(() => {
          setTick(tick => tick + 1)
          schedule()
        }, Math.ceil(next - age))
      }
    }
    schedule()
    return () => window.clearTimeout(timer)
  }, [evidence, started])
  return classifyReadiness(snapshot, performance.now())
}

function machineStatusSummary(machine: MachineReadinessSummary) {
  const labels: Record<string, string> = { observed: 'Runtime reporting', stale: 'Status stale', clock_uncertain: 'Clock uncertain' }
  return machine.terminal ? 'Cleanup pending' : labels[machine.report_state || ''] || (machine.last_config_fetch_at ? 'Config requested' : 'Enrolled')
}

export function MachineReadinessBadge({ machine }: { machine: MachineReadinessSummary }) {
  const state = useReadiness(machine)
  return <div className="machine-readiness"><span className={`machine-status ${state}`}><span className="status-dot" />{readinessLabels[state]}</span><span className="machine-report-state">{machineStatusSummary(machine)}</span></div>
}

const reasons: Record<string, string> = {
  runtime_pending: 'Waiting for Node deployment to become ready',
  certificate_pending: 'Waiting for tunnel certificates',
  tls_or_route_pending: 'Waiting for tunnel endpoints to pass verification',
  discovery_excluded: 'This node is excluded from fleet discovery',
  secrets_unavailable: 'Secret delivery is unavailable; startup is waiting for secret preflight', secrets_denied: 'Secret delivery was denied; check assignment access', secret_missing: 'A required secret or key is missing', secret_invalid: 'Delivered secret data could not be validated',
  onchain_not_ready: 'Onchain Node is not ready; inspect credential delivery, retained onchain state, RPC and rate source', sandbox_pending: 'Sandbox or Pod network setup is pending', invalid_app_payload: 'Downloaded app input is invalid',
  onchain_pending: 'Waiting for the target onchain configuration', onchain_incompatible: 'App price is incompatible with the target onchain mode', resource_refused: 'Insufficient resources for this assignment', cleanup_prerequisite: 'Waiting for previous revision cleanup', cleanup_pending: 'Waiting for earlier instance cleanup', generation_failed: 'App configuration could not be rendered', invalid_definition: 'App definition is invalid', unsupported_instance_mode: 'Instance lifetime is not supported', unsupported_stop_signal: 'Configured stop signal is not supported', image_pull_failed: 'Container image could not be pulled', container_start_failed: 'Container could not start', startup_failed: 'Startup deadline expired', readiness_failed: 'Configured readiness check failed', memory_limit: 'Container exceeded its memory limit', scheduling_refused: 'Kubernetes refused scheduling', isolation_failed: 'Sandbox isolation could not start', state_recovery_failed: 'App Reconciler state recovery failed; management repair remains available', registration_reset: 'Node registration was lost or expired', node_registration_recreated: 'Node registration was recreated; previous work is unconfirmed', clock_uncertain: 'Observation clock is uncertain', process_lost: 'App process disappeared', process_failed: 'App process failed', observation_pending: 'App state could not be observed', fetch_or_publication_failed: 'Configuration fetch or artifact publication failed', access_denied: 'Discovery bearer authentication was denied', credential_unavailable: 'Discovery credential is unavailable', unreported: 'No observation received', input_regression: 'Older app input was refused', registration_failed: 'Node registration failed', registration_pending: 'Node registration is pending', node_unavailable: 'Node registration service is unreachable', node_request_failed: 'Node rejected the registration request', heartbeat_response: 'Node registration response is invalid', heartbeat_ttl: 'Node registration expiry is invalid', registration_auth_failed: 'Node rejected registration credentials', tls_pending: 'Waiting for TLS', drain_pending: 'Drain or cleanup is pending', runtime_offline: 'Runtime has no fresh report', reconcile_failed: 'Flux resource reconciliation failed', cleanup_failed: 'Resource cleanup failed', ownership_conflict: 'Tunnel resource ownership conflicts', provisioning_pending: 'Tunnel provisioning is pending', ingress_pending: 'Waiting for ingress authentication configuration', denied_destination: 'Discovery destination was refused', dns: 'Discovery DNS lookup failed', timeout: 'Discovery collection timed out', http_error: 'Discovery source returned an error', redirect: 'Discovery source redirected the request', transport_error: 'Discovery source could not be reached', unsupported_stop_signal_field: 'Host does not support the requested stop signal', stop_signal_unverified: 'The configured stop signal could not be verified; admission is withheld', process_failed_to_start: 'App process failed to start', registration_cleanup_failed: 'Registration cleanup failed', clock_state_unavailable: 'Clock state is unavailable', app_cleanup_pending: 'App cleanup remains pending', drain_timeout: 'Drain deadline expired', input_unavailable: 'App input is unavailable', publication_failed: 'App artifact publication failed', serving_failed: 'App artifact serving failed', failed: 'Component reported failure', offline: 'Component has no ready observation', connector_observation_stale: 'No fresh connector readiness observation', applying: 'Resource reconciliation is pending', ready: 'Ready', removed: 'Removed', rollout_pending: 'Waiting for the new configuration to apply', cleanup_unconfirmed: 'Cleanup is unconfirmed',
}
function reason(code?: string) { return code ? reasons[code] || code.replaceAll('_', ' ') : '' }
function date(value?: string | null) { return value && Date.parse(value) > 0 ? new Date(value).toLocaleString() : 'Unobserved' }
function alive(value: string | undefined, now: number) { return !!value && Date.parse(value) > now }
function freshObservation(c: Component | undefined, clock: number) { return !!c?.received_at && c.fresh && !c.clock_uncertain && alive(c.expires_at, clock) }

function currentAssignment(view: MachineObservation, runner: Component | undefined, a: Assignment, clock: number) {
  const apps = runner?.apps
  if (!freshObservation(runner, clock) || !runner?.current || apps?.desired_generation !== view.requested.generation) return undefined
  if (view.delivered?.generation === view.requested.generation && view.delivered.apps_digest && apps.desired_digest !== view.delivered.apps_digest) return undefined
  // Assignment preflight describes desired input; artifact stages retain their
  // original identities and cannot establish that an old Flux failure cleared.
  return apps.assignments?.find(o => o.revision_id === a.revision_id && o.generation === a.generation && o.activation_generation === a.activation_generation)
}

function WorkReadiness({ view }: { view: MachineObservation }) {
  const state = useReadiness(view)
  const evidence = view.readiness_evidence
  const age = performance.now() - (view.readinessRequestedAt ?? -Infinity)
  const inactive = state === 'inactive'
  const title = state === 'unverified' ? 'Work readiness unverified' : readinessLabels[state]
  const HeadingIcon = state === 'ready' ? CircleCheck : inactive || state === 'blocked' ? CircleAlert : CircleHelp

  type Check = { label: string; state: 'ready' | 'pending' | 'blocked' | 'unverified' | 'disabled'; detail?: string }
  const checks: Check[] = []
  if (evidence) {
    const add = (label: string, observation: typeof evidence.node | undefined) => {
      const state = observation ? observationState(observation, age) : 'disabled'
      checks.push({ label, state, detail: state !== 'unverified' ? reason(observation?.reason) : undefined })
    }
    add('Node deployment', evidence.node)
    if (evidence.onchain) add('Onchain admission', evidence.onchain)
    const { apps } = evidence
    const { admitted, blocker, pending, ready } = appEvidenceAt(apps, age)
    const appIssue = reason((blocker ? apps.blocker : pending ? apps.pending : undefined)?.reason)
    checks.push({
      label: 'Apps', state: ready ? 'ready' : blocker || (apps.complete && apps.requested === 0) ? 'blocked' : pending ? 'pending' : 'unverified',
      detail: apps.complete && apps.requested === 0 ? 'No apps assigned.' :
        `${admitted} of ${apps.requested} requested replicas have current Node admission evidence.${appIssue ? ` ${appIssue}.` : ''}`,
    })
    add('Tunnel provisioning', evidence.ingress)
    add('Discovery inventory', evidence.discovery)
  }

  const status = { ready: 'Ready', pending: 'Pending', blocked: 'Blocked', unverified: 'Unverified', disabled: 'Disabled' }
  return <section className={`work-readiness ${state}`} aria-label="Work readiness">
    <div className="readiness-heading"><HeadingIcon size={23} aria-hidden="true" /><div><h4>{title}</h4>{inactive && <p>{view.lifecycle === 'draining' ? 'This node is draining for removal.' : 'This enrollment is retired. Cleanup evidence is shown below.'}</p>}</div></div>
    {checks.length > 0 && <ul className="readiness-checks">{checks.map(check => {
      const Icon = check.state === 'ready' ? CircleCheck : check.state === 'blocked' ? CircleAlert : check.state === 'disabled' ? Minus : CircleHelp
      return <li className={`readiness-check ${check.state}`} key={check.label}><Icon size={18} aria-hidden="true" /><div><div className="readiness-check-heading"><strong>{check.label}</strong><span>{status[check.state]}</span></div>{check.detail && <p>{check.detail}</p>}</div></li>
    })}</ul>}
    <p className="readiness-note">External app reachability remains unverified.</p>
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
        setNow(arrived); setView({ ...data, readinessRequestedAt: started }); setProblem('')
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
  const fresh = (c?: Component) => freshObservation(c, clock)
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
      <WorkReadiness view={view} />
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
        const current = currentAssignment(view, runner, a, clock)
        const instances = apps?.instances.filter(i => i.revision_id === a.revision_id) || []
        return <article className="observed-assignment" key={a.revision_id} aria-label={`Observed ${a.name} revision ${a.revision}`}>
          <h4>{a.name} / revision {a.revision} <span className="muted">{a.version}</span></h4>
          <p>Desired {a.desired === 'absent' ? 'removal' : `${a.replicas} replicas`} · generation {a.generation} · activation {a.activation_generation}. Observed generation {observed?.generation || 'unknown'}.</p>
          <p><strong>Applied:</strong> {a.completed_at ? a.desired === 'absent' ? 'Removed — cleanup confirmed' : 'Resource reconciliation confirmed' : a.failure ? 'Resource reconciliation unconfirmed' : 'Pending resource reconciliation'} · <strong>Configured health:</strong> {current && alive(current.probe_expires_at, clock) ? `${current.ready} ready` : 'Unverified / stale'} · <strong>Registered:</strong> {current && alive(current.node_expires_at, clock) ? `${current.registered} confirmed` : 'Unverified / stale'}</p>
          <p className="muted">{a.health.type.toUpperCase()} readiness · every {a.health.interval} · timeout {a.health.timeout} · {a.health.failure_threshold} failures to withdraw readiness</p>
          {current?.reason && <p className="notice error" role="alert">Current assignment blocker: {reason(current.reason)}</p>}
          {a.failure && a.failure !== current?.reason && <p className={current?.reason ? 'muted' : 'notice error'} role={current?.reason ? undefined : 'alert'}>Last reconciliation diagnostic: {reason(a.failure)}</p>}
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
