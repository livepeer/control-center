// Edge routes for the Control Center UI hostname. Static assets, including the
// SPA fallback for /invite and /auth/callback, are served by Workers Static
// Assets. wrangler.jsonc sends only the paths below to this script first, so
// they can never fall back to the UI's index.html.
//
// Bootstrap files live in R2 with the layout written by
// tools/publish-bootstrap.py:
//   bootstrap.sh                       the active loader (mutable)
//   releases/<id>/<file>               immutable published releases

interface BootstrapObject {
  readonly body: ReadableStream
  readonly httpEtag: string
  readonly size: number
}

interface BootstrapBucket {
  get(key: string): Promise<BootstrapObject | null>
  head(key: string): Promise<Omit<BootstrapObject, 'body'> | null>
}

export interface Env {
  BOOTSTRAP: BootstrapBucket
}

const releaseFiles: Record<string, string> = {
  'bootstrap.sh': 'text/x-shellscript',
  'runtime-bootstrap.tar.gz': 'application/gzip',
  'SHA256SUMS': 'text/plain; charset=utf-8',
  'release.json': 'application/json',
}
// Matches release IDs accepted by tools/package-bootstrap.py.
const releasePath = /^\/bootstrap\/releases\/([a-zA-Z0-9][a-zA-Z0-9._-]{0,127})\/([^/]+)$/

const baseHeaders = { 'X-Content-Type-Options': 'nosniff' }

function text(status: number, message: string, headers: Record<string, string> = {}) {
  return new Response(message + '\n', { status, headers: { ...baseHeaders, 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', ...headers } })
}

function locate(pathname: string): { key: string; type: string; cache: string } | null {
  if (pathname === '/bootstrap.sh') return { key: 'bootstrap.sh', type: releaseFiles['bootstrap.sh'], cache: 'no-cache' }
  const match = releasePath.exec(pathname)
  if (!match || match[1].includes('..') || !Object.hasOwn(releaseFiles, match[2])) return null
  return { key: `releases/${match[1]}/${match[2]}`, type: releaseFiles[match[2]], cache: 'public, max-age=31536000, immutable' }
}

async function bootstrap(request: Request, env: Env, pathname: string) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return text(405, 'Method not allowed.', { Allow: 'GET, HEAD' })
  const target = locate(pathname)
  if (!target) return text(404, 'Not found.')
  const head = request.method === 'HEAD'
  const object = head ? await env.BOOTSTRAP.head(target.key) : await env.BOOTSTRAP.get(target.key)
  if (!object) return text(404, 'Not found.')
  const headers = { ...baseHeaders, 'Content-Type': target.type, 'Cache-Control': target.cache, 'Content-Length': String(object.size), ETag: object.httpEtag }
  return new Response(head ? null : (object as BootstrapObject).body, { status: 200, headers })
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url)
    if (pathname === '/api' || pathname.startsWith('/api/')) {
      // The API has its own origin. A page still calling /api here is an
      // outdated release; answer with JSON so it shows a clear error.
      return new Response(JSON.stringify({ error: 'This console version is out of date. Reload the page.' }), { status: 404, headers: { ...baseHeaders, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } })
    }
    if (pathname === '/bootstrap' || pathname === '/bootstrap.sh' || pathname.startsWith('/bootstrap/')) {
      try { return await bootstrap(request, env, pathname) }
      catch { return text(503, 'Bootstrap files are temporarily unavailable. Retry shortly.') }
    }
    return text(404, 'Not found.')
  },
}
