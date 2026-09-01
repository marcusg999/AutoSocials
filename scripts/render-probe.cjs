/**
 * RUNTIME DATA-ACCESS PROBE.
 *
 * Loaded into `next start` with --require by scripts/check-no-secrets.ts.
 *
 * Thirteen review rounds established that no static model answers the question a
 * dataless page's guard is asking. The property is "rendering this page reads no
 * tenant data"; every static model has been a proxy for it -- which module-naming
 * syntax appears, which module paths are reached -- and each proxy was narrower than
 * the property. The last one failed because the set of module PATHS is invariant
 * under editing any module already on the list: a read added inside
 * lib/security/csrf.ts, which /login has always run, changed nothing the guard
 * looked at and served every tenant to an anonymous browser.
 *
 * So this stops modelling and watches. It records the data reads a render actually
 * performs, at the two places a read can leave this process:
 *
 *   - global fetch, which is how supabase-js talks to PostgREST, and how a raw
 *     `fetch()` to /rest/v1 would too;
 *   - the `pg` driver, for a direct connection that never touches fetch.
 *
 * Auth traffic is NOT a data read: /login legitimately asks the auth server who the
 * caller is before rendering. Only /rest/v1 (PostgREST) and a live SQL connection
 * count, which is exactly the line the property draws.
 */
const { appendFileSync } = require('node:fs')

const LOG = process.env.RENDER_PROBE_LOG
if (LOG) {
  const record = (kind, detail) => {
    try { appendFileSync(LOG, JSON.stringify({ kind, detail }) + '\n') } catch { /* best effort */ }
  }

  const realFetch = globalThis.fetch
  globalThis.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : (input && input.url) || String(input)
    // PostgREST is the data plane. /auth/v1 is the auth plane and is expected.
    if (/\/rest\/v1\//.test(url)) record('postgrest', url)
    return realFetch.call(this, input, init)
  }

  // The SOCKET, not the module loader.
  //
  // The first version of this hooked Module._load to catch `require('pg')`. It works
  // in plain Node and is useless here: Next's bundler resolves `await import('pg')`
  // inside a server component without going through Node's loader at all. Verified
  // the hard way -- the injected leak ran 29 times, imported pg, constructed a
  // Client and reached a real Postgres, while the probe recorded nothing and the
  // scan reported success. That is the same false green this probe exists to end.
  //
  // Every database driver, bundled or not, ends up opening a TCP socket. net is a
  // core module the bundler cannot inline, so this is the one seam nothing gets past.
  const net = require('node:net')
  const realConnect = net.Socket.prototype.connect
  net.Socket.prototype.connect = function (...args) {
    const options = typeof args[0] === 'object' && args[0] !== null ? args[0] : {}
    const port = String(options.port ?? args[0] ?? '')
    const host = String(options.host ?? args[1] ?? 'localhost')
    // The Supabase stub is the auth plane and is expected during a render. Anything
    // else an anonymous render opens is a direct data connection.
    if (port && port !== String(process.env.RENDER_PROBE_ALLOWED_PORT ?? '')) {
      record('socket', `${host}:${port}`)
    }
    return realConnect.apply(this, args)
  }
}
