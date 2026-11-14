import { useCallback, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import type { Session } from '@supabase/supabase-js'
import { api, APIError } from './api'

type Orchestrator = { address: string; display_name: string }
type Props = { session: Session; header: (selector: ReactNode) => ReactNode; children: (address: string | null, authorityFailure: (error: unknown) => void) => ReactNode }

export function OrchestratorWorkspace({ session, header, children }: Props) {
  const [orchestrators, setOrchestrators] = useState<Orchestrator[] | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [problem, setProblem] = useState('')
  const active = useRef<AbortController | null>(null)
  const latestSession = useRef(session)
  latestSession.current = session
  const storageKey = `lpcc-orchestrator:${session.user.id}`
  const refresh = useCallback(async () => {
    active.current?.abort()
    const controller = new AbortController(); active.current = controller
    try {
      const data = await api<{ orchestrators: Orchestrator[] }>(latestSession.current, '/api/orchestrators', { signal: controller.signal })
      if (controller.signal.aborted) return
      const list = [...data.orchestrators].sort((a,b) => a.address.localeCompare(b.address))
      let saved: string | null = null
      try { saved = localStorage.getItem(storageKey) } catch { /* Selection still works without browser storage. */ }
      setSelected(current => list.some(o => o.address === current) ? current : list.find(o => o.address === saved)?.address ?? list[0]?.address ?? null)
      setOrchestrators(list); setProblem('')
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
  return <>
    {header(<label className="orchestrator-picker"><span>Orchestrator</span><select aria-label="Orchestrator" value={selected ?? ''} disabled={!orchestrators?.length} onChange={e => setSelected(e.target.value)}>
      {!selected && <option value="">{problem ? 'Orchestrators unavailable' : orchestrators ? 'No orchestrators' : 'Loading orchestrators…'}</option>}
      {orchestrators?.map(o => <option key={o.address} value={o.address}>{o.display_name ? `${o.display_name} · ` : ''}{o.address}</option>)}
    </select></label>)}
    {problem ? <div className="orchestrator-notice notice error" role="alert">{problem}<button className="button" onClick={() => void refresh()}>Retry orchestrators</button></div> : orchestrators === null ? <p className="orchestrator-notice" role="status">Loading orchestrators…</p> : !orchestrators.length && <p className="orchestrator-notice" role="status">No orchestrators are linked to your account. Contact your operator to arrange access.</p>}
    {children(selected,authorityFailure)}
  </>
}
