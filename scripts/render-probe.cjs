/**
 * RUNTIME DATA-READ PROBE.
 *
 * Loaded into `next build` and `next start` with --require by
 * scripts/check-no-secrets.ts.
 *
 * Fourteen review rounds established that no static model answers the question the
 * dataless-page guard asks. The property is "rendering this page reads no tenant
 * data"; every model has been a proxy narrower than the property. The first runtime
 * version was narrower too, and its proxy was:
 *
 *     "a socket handshake started during this request, to a port I don't recognise"
 *
 * A data read is not a handshake. It is a handshake PLUS every query afterwards on
 * that socket PLUS every byte baked into a cache by an earlier render. So a POOLED
 * connection -- opened once at boot, reused forever -- performed a live cross-tenant
 * read for an anonymous browser with the probe log empty and the scan reporting
 * success. This version watches the traffic, not the connection.
 */
const { appendFileSync } = require('node:fs')

const LOG = process.env.RENDER_PROBE_LOG
if (LOG) {
  const ALLOWED_PORT = String(process.env.RENDER_PROBE_ALLOWED_PORT ?? '')
  const record = (kind, detail) => {
    try { appendFileSync(LOG, JSON.stringify({ kind, detail }) + '\n') } catch { /* best effort */ }
  }

  // The data plane, wherever it is spoken. /auth/v1 is the auth plane and is
  // expected: /login legitimately asks the auth server who the caller is.
  const DATA_PATH = /\/rest\/v1\/|\/graphql\/v1|\/functions\/v1\//
  const describe = (value) => {
    try { return typeof value === 'string' ? value : String(value?.href ?? value?.url ?? '') }
    catch { return '' }
  }

  // ---- 1. fetch, which is how supabase-js speaks to PostgREST ----------------
  const realFetch = globalThis.fetch
  if (typeof realFetch === 'function') {
    globalThis.fetch = function (input, init) {
      const url = describe(input)
      if (DATA_PATH.test(url)) record('postgrest', url)
      return realFetch.call(this, input, init)
    }
  }

  // ---- 2. node:http / node:https, which never touch global fetch -------------
  //
  // The data plane and the auth plane share a host and a port, so a port-based
  // exemption cannot tell them apart: a `node:http` GET of /rest/v1/posts on the
  // allowed port was invisible to BOTH seams at once. The path is what separates
  // them, so the path is what is read.
  for (const moduleName of ['node:http', 'node:https']) {
    const mod = require(moduleName)
    for (const method of ['request', 'get']) {
      const real = mod[method]
      mod[method] = function (...args) {
        try {
          for (const arg of args) {
            if (typeof arg === 'string' && DATA_PATH.test(arg)) record('http', arg)
            else if (arg && typeof arg === 'object' && typeof arg.path === 'string'
                     && DATA_PATH.test(arg.path)) record('http', arg.path)
          }
        } catch { /* never let the probe change behaviour */ }
        return real.apply(this, args)
      }
    }
  }

  // ---- 3. every byte written to a database socket ---------------------------
  //
  // Sockets are tagged at connect and inspected at WRITE, because a query on an
  // already-open connection performs no connect. That is the whole of finding F1.
  const net = require('node:net')

  /**
   * Node normalises connect arguments before calling Socket.prototype.connect, so
   * args[0] can be an ARRAY holding a null-prototype options object. The previous
   * version did String(args[0]) on that and threw `Cannot convert object to
   * primitive value` from inside the hook -- crashing every honest node:http render
   * with a 500 -- and, on the non-throwing path, produced the port "[object Object],"
   * which never equals the allowed port, so honest auth traffic was reported as a
   * tenant data read. A probe that both breaks and slanders correct code is worse
   * than no probe: it gets deleted.
   */
  const destinationOf = (args) => {
    const first = Array.isArray(args[0]) ? args[0][0] : args[0]
    if (first && typeof first === 'object') {
      return { port: String(first.port ?? first.path ?? ''), host: String(first.host ?? 'localhost') }
    }
    return { port: String(first ?? ''), host: String(args[1] ?? 'localhost') }
  }

  const realConnect = net.Socket.prototype.connect
  net.Socket.prototype.connect = function (...args) {
    try {
      const { port, host } = destinationOf(args)
      // A connection to anything that is not the Supabase host is a direct database
      // connection. Tag it; every write on it is then a read.
      this.__probeDataSocket = port !== '' && port !== ALLOWED_PORT ? `${host}:${port}` : null
    } catch { this.__probeDataSocket = null }
    return realConnect.apply(this, args)
  }

  const realWrite = net.Socket.prototype.write
  net.Socket.prototype.write = function (...args) {
    if (this.__probeDataSocket) record('query', this.__probeDataSocket)
    return realWrite.apply(this, args)
  }
}
