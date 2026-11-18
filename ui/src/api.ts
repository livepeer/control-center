import type { Session } from '@supabase/supabase-js'

// Deployed builds call the API origin directly (see .env.production). Local
// development leaves it empty so the Vite proxy serves /api on the same origin.
const apiBase = (import.meta.env.VITE_CONTROLCENTER_API_URL ?? '').replace(/\/$/, '')

export function apiURL(path: string) {
  return apiBase + path
}

export class APIError extends Error {
  constructor(public status: number, message: string, public code = "", public fields: {path: string; code: string; message: string}[] = []) { super(message) }
}

export async function api<T>(session: Session, path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  headers.set('Authorization', `Bearer ${session.access_token}`)
  const response = await fetch(apiURL(path), { ...options, headers, cache: 'no-store', credentials: 'omit' })
  if (response.status === 204) return undefined as T
  let body
  try { body = await response.json() }
  catch (error) { if (response.ok) throw error }
  if (!response.ok) throw new APIError(response.status, typeof body?.error === 'string' ? body.error : 'The request failed. Please try again.', typeof body?.code === 'string' ? body.code : '', Array.isArray(body?.fields) ? body.fields : [])
  return body as T
}
