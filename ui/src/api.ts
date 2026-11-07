import type { Session } from '@supabase/supabase-js'

export class APIError extends Error {
  constructor(public status: number, message: string, public code = "", public fields: {path: string; code: string; message: string}[] = []) { super(message) }
}

export async function api<T>(session: Session, path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  headers.set('Authorization', `Bearer ${session.access_token}`)
  const response = await fetch(path, { ...options, headers, cache: 'no-store' })
  if (response.status === 204) return undefined as T
  let body
  try { body = await response.json() }
  catch (error) { if (response.ok) throw error }
  if (!response.ok) throw new APIError(response.status, typeof body?.error === 'string' ? body.error : 'The request failed. Please try again.', typeof body?.code === 'string' ? body.code : '', Array.isArray(body?.fields) ? body.fields : [])
  return body as T
}
