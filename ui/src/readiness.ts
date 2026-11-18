export type ReadinessState = 'ready' | 'pending' | 'partial' | 'unverified' | 'blocked' | 'inactive'

type ReadinessObservation = {
  state: 'ready' | 'pending' | 'unverified' | 'blocked'
  reason?: string
  valid_for_ms?: number
}

export type ReadinessEvidence = {
  node: ReadinessObservation
  onchain?: ReadinessObservation
  ingress?: ReadinessObservation
  discovery?: ReadinessObservation
  apps: {
    requested: number
    complete: boolean
    applied: boolean
    admitted: number
    admitted_valid_for_ms?: number
    last_admission_for_ms?: number
    blocker?: ReadinessObservation
    pending?: ReadinessObservation
  }
}

export type ReadinessSnapshot = {
  terminal?: boolean
  lifecycle?: string
  readiness_evidence?: ReadinessEvidence
  readinessRequestedAt?: number
}

export function observationState(observation: ReadinessObservation | undefined, age: number) {
  if (!observation || (observation.valid_for_ms !== undefined && age >= observation.valid_for_ms)) return 'unverified'
  if (observation.state === 'ready' && !observation.valid_for_ms) return 'unverified'
  return observation.state
}

export function appEvidenceAt(apps: ReadinessEvidence['apps'], age: number) {
  const countCurrent = age < (apps.admitted_valid_for_ms ?? 0)
  const admitted = countCurrent ? apps.admitted : age < (apps.last_admission_for_ms ?? 0) ? 1 : 0
  const blocker = observationState(apps.blocker, age) === 'blocked'
  const pending = observationState(apps.pending, age) === 'pending'
  let state: Exclude<ReadinessState, 'inactive'> = 'unverified'
  if (apps.complete && apps.requested === 0) state = 'blocked'
  else if (admitted > 0) state = countCurrent && apps.complete && apps.applied && admitted === apps.requested && !blocker && !pending ? 'ready' : 'partial'
  else if (blocker) state = 'blocked'
  else if (pending) state = 'pending'
  return { state, admitted, blocker, pending }
}

export function classifyReadiness(snapshot: ReadinessSnapshot, now: number): ReadinessState {
  if (snapshot.terminal || ['draining', 'cleanup_pending', 'removed'].includes(snapshot.lifecycle ?? '')) return 'inactive'
  const evidence = snapshot.readiness_evidence
  if (!evidence) return 'unverified'
  const age = snapshot.readinessRequestedAt === undefined ? Infinity : now - snapshot.readinessRequestedAt
  const checks = [observationState(evidence.node, age), ...[evidence.onchain, evidence.ingress, evidence.discovery]
    .filter(check => check !== undefined)
    .map(check => observationState(check, age))]
  const apps = appEvidenceAt(evidence.apps, age)
  if (checks.includes('blocked') || apps.state === 'blocked') return 'blocked'
  if (checks.every(state => state === 'ready')) return apps.state
  return apps.pending || checks.includes('pending') ? 'pending' : 'unverified'
}

export function nextReadinessExpiry(evidence: ReadinessEvidence, age: number) {
  const { node, onchain, ingress, discovery, apps } = evidence
  return Math.min(...[node?.valid_for_ms, onchain?.valid_for_ms, ingress?.valid_for_ms, discovery?.valid_for_ms,
    apps.blocker?.valid_for_ms, apps.pending?.valid_for_ms, apps.admitted_valid_for_ms, apps.last_admission_for_ms]
    .filter((expiry): expiry is number => expiry !== undefined && expiry > age))
}
