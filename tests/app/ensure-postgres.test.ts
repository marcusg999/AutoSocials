/**
 * The parts of the "start a Postgres" script that can be wrong quietly.
 *
 * Starting a service is either observable or it isn't — you run it and the tests
 * pass, or they don't. What is not observable is the reading: a cluster version
 * parsed out of the wrong column, or an authentication failure mistaken for a
 * stopped server, both produce a script that looks like it works and does the
 * wrong thing on somebody else's machine.
 *
 * The classifier is the one that matters most. "Nothing is listening" and "a
 * server answered and said no" arrive through completely different channels, and
 * confusing them means the script tries to start a server that is already running
 * and then reports that it could not — hiding the real message, which was that
 * the password is wrong.
 */
import { describe, expect, test } from 'vitest'

import {
  classifyConnectionError, isPostgresService, parseBrewServices, parseClusters,
} from '../../scripts/ensure-postgres'

describe('what a failed connection means', () => {
  test('a refused socket is a server that is not there', () => {
    expect(classifyConnectionError({ code: 'ECONNREFUSED' })).toBe('unreachable')
    expect(classifyConnectionError({ code: 'ENOENT' })).toBe('unreachable')
  })

  /**
   * The important half. A server that is up and rejecting the password does not
   * need starting, and trying would replace a precise message with a vague one.
   */
  test('a rejected password is a server that IS there', () => {
    expect(classifyConnectionError({ code: '28P01' })).toBe('refused-credentials')
    expect(classifyConnectionError({ code: '3D000' })).toBe('refused-credentials')
    expect(classifyConnectionError(
      new Error('password authentication failed for user "postdeck"')))
      .toBe('refused-credentials')
  })

  test('anything else is reported rather than guessed at', () => {
    expect(classifyConnectionError(new Error('certificate has expired'))).toBe('other')
    expect(classifyConnectionError(undefined)).toBe('other')
  })
})

describe('reading pg_lsclusters', () => {
  const OUTPUT = [
    'Ver Cluster Port Status Owner    Data directory              Log file',
    '16  main    5432 down   postgres /var/lib/postgresql/16/main /var/log/postgresql/x.log',
    '17  extra   5433 online postgres /var/lib/postgresql/17/extra /var/log/postgresql/y.log',
  ].join('\n')

  /**
   * The version comes out of the tool rather than out of a constant. Hardcoding
   * 16 is exactly the sort of thing that works until the day somebody upgrades.
   */
  test('takes the version and name from the row, whatever they are', () => {
    expect(parseClusters(OUTPUT)).toEqual([
      { version: '16', name: 'main', status: 'down' },
      { version: '17', name: 'extra', status: 'online' },
    ])
  })

  test('skips the header rather than treating it as a cluster', () => {
    expect(parseClusters(OUTPUT).map((c) => c.version)).not.toContain('Ver')
  })

  test('no clusters at all is an empty list, not a crash', () => {
    expect(parseClusters('Ver Cluster Port Status Owner Data directory Log file')).toEqual([])
    expect(parseClusters('')).toEqual([])
  })
})

describe('reading brew services list', () => {
  const OUTPUT = [
    'Name          Status  User   File',
    'postgresql@16 none    marcus ~/Library/LaunchAgents/homebrew.mxcl.postgresql@16.plist',
    'redis         started marcus ~/Library/LaunchAgents/homebrew.mxcl.redis.plist',
  ].join('\n')

  test('reads each service and its status', () => {
    expect(parseBrewServices(OUTPUT)).toEqual([
      { name: 'postgresql@16', status: 'none' },
      { name: 'redis', status: 'started' },
    ])
  })

  test('only the postgres formulae count as a postgres', () => {
    // A match on "postgres" alone would try to start postgrest, pgadmin, or
    // anything else with the word in its name.
    expect(isPostgresService('postgresql@16')).toBe(true)
    expect(isPostgresService('postgresql')).toBe(true)
    expect(isPostgresService('postgresql@14.5')).toBe(true)
    expect(isPostgresService('redis')).toBe(false)
    expect(isPostgresService('postgrest')).toBe(false)
    expect(isPostgresService('pgadmin4')).toBe(false)
  })
})
