import { useCallback, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { Session } from '@supabase/supabase-js'
import { api, APIError } from './api'
import { InvitationAcceptance, OrchestratorMembers } from './orchestrator-members'

type Orchestrator = { address: string; display_name: string }
type Props = { session: Session; invitation: string | null; clearInvitation: () => void; header: (selector: ReactNode) => ReactNode; children: (address: string | null, authorityFailure: (error: unknown) => void) => ReactNode }

export function OrchestratorWorkspace({ session, invitation, clearInvitation, header, children }: Props) {
  const [orchestrators, setOrchestrators] = useState<Orchestrator[] | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [problem, setProblem] = useState('')
  const [mode, setMode] = useState<'offchain' | 'onchain' | null>(null)
  const [adding, setAdding] = useState(false)
  const [address, setAddress] = useState('')
  const [challenge, setChallenge] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [signature, setSignature] = useState('')
  const [working, setWorking] = useState(false)
  const [claimProblem, setClaimProblem] = useState('')
  const active = useRef<AbortController | null>(null)
  const preferredSelection = useRef<string | null>(null)
  const latestSession = useRef(session)
  latestSession.current = session
  const storageKey = `lpcc-orchestrator:${session.user.id}`
  const refresh = useCallback(async (preferred?: string) => {
    if (preferred) preferredSelection.current = preferred
    active.current?.abort()
    const controller = new AbortController(); active.current = controller
    try {
      const [data, config] = await Promise.all([
        api<{ orchestrators: Orchestrator[] }>(latestSession.current, '/api/orchestrators', { signal: controller.signal }),
        api<{ mode: 'offchain' | 'onchain' }>(latestSession.current, '/api/operator/config', { signal: controller.signal }),
      ])
      if (controller.signal.aborted) return
      const list = [...data.orchestrators].sort((a,b) => a.address.localeCompare(b.address))
      let saved: string | null = null
      try { saved = localStorage.getItem(storageKey) } catch { /* Selection still works without browser storage. */ }
      const wanted = preferredSelection.current
      setSelected(current => list.find(o => o.address === wanted)?.address ?? (list.some(o => o.address === current) ? current : list.find(o => o.address === saved)?.address ?? list[0]?.address ?? null))
      if (list.some(o => o.address === wanted)) preferredSelection.current = null
      setOrchestrators(list); setMode(config.mode); setProblem('')
    } catch (error) {
      if (!controller.signal.aborted) { setProblem(error instanceof Error ? error.message : 'Could not load orchestrators.') }
    }
  }, [storageKey])
  const authorityFailure = useCallback((error: unknown) => {
    if (error instanceof APIError && [401,403].includes(error.status)) {
      void refresh()
    }
  }, [refresh])
  useEffect(() => {
    const load = () => { void refresh() }
    load(); window.addEventListener('focus',load)
    return () => { active.current?.abort(); window.removeEventListener('focus',load) }
  }, [refresh,session.access_token])
  useEffect(() => {
    try { if (selected) localStorage.setItem(storageKey,selected) } catch { /* Optional preference. */ }
  }, [selected,storageKey])
  const checkAddress = async () => {
    setWorking(true); setClaimProblem('')
    try {
      const result = await api<{ challenge: string; expires_at: string }>(session, '/api/orchestrators/challenge', { method: 'POST', body: JSON.stringify({ address }) })
      setChallenge(result.challenge); setExpiresAt(result.expires_at); setSignature('')
    } catch (error) { setClaimProblem(error instanceof Error ? error.message : 'Could not check orchestrator.') }
    finally { setWorking(false) }
  }
  const claim = async () => {
    setWorking(true); setClaimProblem('')
    try {
      const result = await api<{ address: string }>(session, '/api/orchestrators', { method: 'POST', body: JSON.stringify(mode === 'onchain' ? { address, challenge, signature } : { address }) })
      setAdding(false); setAddress(''); setChallenge(''); setExpiresAt(''); setSignature('')
      await refresh(result.address)
    } catch (error) { setClaimProblem(error instanceof Error ? error.message : 'Could not add orchestrator.') }
    finally { setWorking(false) }
  }
  const downloadChallenge = () => {
    const url = URL.createObjectURL(new Blob([challenge], { type: 'text/plain' }))
    const link = document.createElement('a')
    link.href = url; link.download = 'orchestrator-claim.jwt'; link.click()
    setTimeout(() => URL.revokeObjectURL(url), 0)
  }
  const reset = () => { setAdding(!adding); setAddress(''); setChallenge(''); setExpiresAt(''); setSignature(''); setClaimProblem('') }
  return <>
    {header(<label className="orchestrator-picker"><span>Orchestrator</span><select aria-label="Orchestrator" value={selected ?? ''} disabled={!orchestrators?.length} onChange={e => { preferredSelection.current = null; setSelected(e.target.value) }}>
      {!selected && <option value="">{problem ? 'Orchestrators unavailable' : orchestrators ? 'No orchestrators' : 'Loading orchestrators…'}</option>}
      {orchestrators?.map(o => <option key={o.address} value={o.address}>{o.display_name ? `${o.display_name} · ` : ''}{o.address}</option>)}
    </select></label>)}
    {problem ? <div className="orchestrator-notice notice error" role="alert">{problem}<button className="button" onClick={() => void refresh()}>Retry orchestrators</button></div> : orchestrators === null ? <p className="orchestrator-notice" role="status">Loading orchestrators…</p> : <div className="orchestrator-notice">
      {!orchestrators.length && <p>No orchestrators are linked to your account.</p>}
      <button className="button" type="button" onClick={reset}>{adding ? 'Cancel' : 'Add orchestrator'}</button>
      {adding && mode && <div className="orchestrator-claim">
        <label>Orchestrator address <input aria-label="Orchestrator address" value={address} onChange={e => { setAddress(e.target.value); setChallenge(''); setExpiresAt(''); setSignature('') }} placeholder={mode === 'offchain' ? 'Optional; defaults to the zero address' : '0x…'} /></label>
        {mode === 'onchain' ? !challenge ? <button className="button" type="button" disabled={working || !address} onClick={() => void checkAddress()}>Check active address</button> : <>
          <p>Address active on Arbitrum One. Download the challenge file, sign its exact bytes, and paste the JSON output’s <code>signature</code>. Any <a href="https://eips.ethereum.org/EIPS/eip-191">EIP-191</a> <code>personal_sign</code> signer, like <a href="https://www.getfoundry.sh/reference/cast/wallet/sign"><code>cast wallet sign</code></a>, also works. The file has no trailing newline. Challenge expires {new Date(expiresAt).toLocaleString()}.</p>
          <button className="button" type="button" onClick={downloadChallenge}>Download orchestrator-claim.jwt</button>
          <pre aria-label="Signing command">livepeer chain sign message --message-file ./orchestrator-claim.jwt --keystore-file &lt;file&gt; --keystore-password-file &lt;file&gt; --output json</pre>
          <label>Signature <input aria-label="Signature" value={signature} onChange={e => setSignature(e.target.value)} placeholder="0x…" /></label>
          <button className="button" type="button" disabled={working || !signature} onClick={() => void claim()}>Claim orchestrator</button>
          <button className="button" type="button" disabled={working} onClick={() => { setChallenge(''); setSignature(''); setClaimProblem('') }}>Check again</button>
        </> : <button className="button" type="button" disabled={working} onClick={() => void claim()}>Add workspace</button>}
        {claimProblem && <p role="alert">{claimProblem}</p>}
      </div>}
    </div>}
    {invitation && <div className="orchestrator-notice"><InvitationAcceptance session={session} token={invitation} dismiss={clearInvitation} accepted={async (address, signal) => { await refresh(address); if (!signal.aborted) clearInvitation() }} /></div>}
    {selected && <div className="orchestrator-notice"><OrchestratorMembers key={`${session.user.id}:${selected}`} session={session} address={selected} authorityFailure={authorityFailure} changed={() => refresh()} /></div>}
    {children(selected,authorityFailure)}
  </>
}
