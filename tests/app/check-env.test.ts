/**
 * The environment checker.
 *
 * Two things are worth testing here and they are not the same thing.
 *
 * The rules: each one exists because that mistake fails somewhere later and less
 * clearly than it should — a service-role key that is really the anon key, two
 * Supabase URLs that disagree, a pooler port that breaks migrations halfway
 * through. A rule that does not fire is a setup session spent guessing.
 *
 * And the property that outranks all of them: NO FINDING EVER CONTAINS A VALUE.
 * This tool reads the one file in the project that holds every secret at once, and
 * prints to a terminal whose scrollback ends up in screenshots and bug reports. A
 * checker that echoes a key while diagnosing it is a worse leak than the mistake.
 */
import { describe, expect, test } from 'vitest'

import { checkEnv, parseEnvFile, type Finding } from '../../scripts/check-env'

/** A complete, valid configuration. Each test spoils exactly one thing. */
const GOOD: Record<string, string> = {
  NEXT_PUBLIC_SUPABASE_URL: 'https://abcdefgh.supabase.co',
  SUPABASE_URL: 'https://abcdefgh.supabase.co',
  NEXT_PUBLIC_SUPABASE_ANON_KEY: 'anon-key-value',
  SUPABASE_SERVICE_ROLE_KEY: 'service-role-key-value',
  DATABASE_URL: 'postgresql://postgres:hunter2@db.abcdefgh.supabase.co:5432/postgres?sslmode=require',
  ADMIN_EMAIL: 'marcus@example.com',
  ADMIN_PASSWORD: 'a-long-enough-password',
  // What `openssl rand -base64 48` actually produces, rather than filler.
  CSRF_SIGNING_SECRET: 'Yk7Qa1pLm9XvZ2rTn4Bc6DfHj8KsLw0EqRtYuIoPaSdFgHjKlZxCvBnM',
  APP_ORIGIN: 'http://localhost:3000',
  TRUSTED_PROXY_COUNT: '0',
}

const errors = (findings: Finding[]) => findings.filter((f) => f.level === 'error')
const about = (findings: Finding[], variable: string) =>
  findings.filter((f) => f.variable === variable)
const withOut = (key: string) => {
  const copy = { ...GOOD }
  delete copy[key]
  return copy
}

describe('a configuration with nothing wrong', () => {
  test('produces no errors and no warnings', () => {
    const findings = checkEnv(GOOD)
    expect(errors(findings)).toEqual([])
    expect(findings.filter((f) => f.level === 'warning')).toEqual([])
  })

  test('still notes the optional features that are switched off', () => {
    // Not a problem — but "why is there no Suggest button" should be answerable
    // without reading the source.
    const notes = checkEnv(GOOD).filter((f) => f.level === 'note')
    expect(notes.map((f) => f.variable)).toEqual(['META_APP_ID', 'ANTHROPIC_API_KEY'])
  })
})

describe('missing and unfilled values', () => {
  test('a missing required variable is an error', () => {
    expect(about(checkEnv(withOut('DATABASE_URL')), 'DATABASE_URL')[0]?.message).toMatch(/missing/)
  })

  test('an empty one is too, rather than being treated as set', () => {
    expect(about(checkEnv({ ...GOOD, ADMIN_EMAIL: '' }), 'ADMIN_EMAIL')[0]?.message)
      .toMatch(/empty/)
  })

  test('a value still identical to .env.example is caught by comparison', () => {
    // The placeholder patterns cannot know every stand-in, so the template is
    // read and compared directly — "unchanged" needs no pattern at all.
    const template = { CSRF_SIGNING_SECRET: 'replace-with-at-least-32-random-characters' }
    const findings = checkEnv({ ...GOOD, CSRF_SIGNING_SECRET: template.CSRF_SIGNING_SECRET }, template)
    expect(about(findings, 'CSRF_SIGNING_SECRET')[0]?.message).toMatch(/placeholder/)
  })

  test('a real secret that happens to start with xxx is NOT called a placeholder', () => {
    // The false positive this check must not make: rejecting a correct value is
    // worse than missing a placeholder, because it sends you looking for a
    // problem that is not there.
    const findings = checkEnv({ ...GOOD, CSRF_SIGNING_SECRET: 'xxxK7Qa1pLm9XvZ2rTn4Bc6DfHj8KsLw0Eq' })
    expect(about(findings, 'CSRF_SIGNING_SECRET')).toEqual([])
  })

  test('but filler made only of x or dots still is', () => {
    expect(about(checkEnv({ ...GOOD, ADMIN_PASSWORD: 'xxxxxxxxxxxx' }), 'ADMIN_PASSWORD')[0]
      ?.message).toMatch(/placeholder/)
  })

  test('and by pattern, when someone edits the placeholder without replacing it', () => {
    expect(about(checkEnv({ ...GOOD, SUPABASE_SERVICE_ROLE_KEY: 'your-service-role-key' }),
      'SUPABASE_SERVICE_ROLE_KEY')[0]?.message).toMatch(/placeholder/)
  })
})

describe('the mistakes that fail late and confusingly', () => {
  /**
   * The quietest failure in the whole setup. seed:admin writes the user through
   * SUPABASE_URL; the app signs in through NEXT_PUBLIC_SUPABASE_URL. Different
   * values means the account exists in one project and is looked for in another,
   * and the only symptom is a login that will not work.
   */
  test('two Supabase URLs that disagree', () => {
    const findings = checkEnv({ ...GOOD, SUPABASE_URL: 'https://different.supabase.co' })
    expect(about(findings, 'SUPABASE_URL')[0]?.message).toMatch(/does not match/)
  })

  test('the same key pasted into both key slots', () => {
    const same = 'the-same-key'
    const findings = checkEnv({
      ...GOOD, NEXT_PUBLIC_SUPABASE_ANON_KEY: same, SUPABASE_SERVICE_ROLE_KEY: same,
    })
    expect(about(findings, 'SUPABASE_SERVICE_ROLE_KEY')[0]?.message).toMatch(/identical/)
  })

  test('the transaction pooler port, which breaks migrations half way through', () => {
    const findings = checkEnv({
      ...GOOD,
      DATABASE_URL: 'postgresql://postgres:pw@aws-0-eu-west-1.pooler.supabase.com:6543/postgres',
    })
    expect(about(findings, 'DATABASE_URL')[0]?.message).toMatch(/6543/)
  })

  test('Supabase\'s own [YOUR-PASSWORD] left in the connection string', () => {
    const findings = checkEnv({
      ...GOOD,
      DATABASE_URL: 'postgresql://postgres:[YOUR-PASSWORD]@db.abcdefgh.supabase.co:5432/postgres',
    })
    expect(about(findings, 'DATABASE_URL').length).toBeGreaterThan(0)
  })

  test('a hosted database with no sslmode is a warning, not a refusal', () => {
    // It may be fine; the migration runner takes SSL from the URL alone, so it is
    // worth saying, and not worth blocking on.
    const findings = checkEnv({
      ...GOOD, DATABASE_URL: 'postgresql://postgres:pw@db.abcdefgh.supabase.co:5432/postgres',
    })
    const sslFinding = about(findings, 'DATABASE_URL')[0]
    expect(sslFinding?.level).toBe('warning')
    expect(sslFinding?.message).toMatch(/sslmode/)
  })

  test('a local database is not nagged about SSL', () => {
    const findings = checkEnv({
      ...GOOD, DATABASE_URL: 'postgresql://postdeck:postdeck@127.0.0.1:5432/postgres',
    })
    expect(about(findings, 'DATABASE_URL')).toEqual([])
  })
})

describe('rules enforced elsewhere, checked here first', () => {
  test('a CSRF secret under 32 characters', () => {
    const findings = checkEnv({ ...GOOD, CSRF_SIGNING_SECRET: 'too-short' })
    expect(about(findings, 'CSRF_SIGNING_SECRET')[0]?.message).toMatch(/at least 32/)
  })

  test('an admin password under 12, which seed:admin would reject anyway', () => {
    const findings = checkEnv({ ...GOOD, ADMIN_PASSWORD: 'short' })
    expect(about(findings, 'ADMIN_PASSWORD')[0]?.message).toMatch(/at least 12/)
  })

  test('a non-numeric proxy count', () => {
    expect(about(checkEnv({ ...GOOD, TRUSTED_PROXY_COUNT: 'one' }), 'TRUSTED_PROXY_COUNT'))
      .toHaveLength(1)
  })

  test('an APP_ORIGIN with a path on it', () => {
    const findings = checkEnv({ ...GOOD, APP_ORIGIN: 'http://localhost:3000/dashboard' })
    expect(about(findings, 'APP_ORIGIN')[0]?.level).toBe('warning')
  })
})

describe('optional features', () => {
  test('half a Meta app is an error, because it cannot work', () => {
    const findings = checkEnv({ ...GOOD, META_APP_ID: '123456' })
    expect(about(findings, 'META_APP_SECRET')[0]?.level).toBe('error')
  })

  test('both halves set produces neither error nor note', () => {
    const findings = checkEnv({ ...GOOD, META_APP_ID: '123456', META_APP_SECRET: 'a-secret' })
    expect(about(findings, 'META_APP_ID')).toEqual([])
    expect(about(findings, 'META_APP_SECRET')).toEqual([])
  })

  test('an unknown NEXT_PUBLIC_ variable is an error, because the prefix publishes it', () => {
    // The lesson from G107, as a setup check: renaming a secret to NEXT_PUBLIC_
    // anything inlines it into the browser bundle.
    const findings = checkEnv({ ...GOOD, NEXT_PUBLIC_DATABASE_URL: 'postgres://...' })
    expect(about(findings, 'NEXT_PUBLIC_DATABASE_URL')[0]?.message).toMatch(/browser bundle/)
  })
})

/**
 * The property that outranks every rule above.
 */
describe('the report never contains a value', () => {
  test('not even for the variables it is complaining about', () => {
    const secrets = {
      NEXT_PUBLIC_SUPABASE_URL: 'https://one.supabase.co',
      SUPABASE_URL: 'https://two.supabase.co',
      NEXT_PUBLIC_SUPABASE_ANON_KEY: 'SECRET-ANON-abcdef',
      SUPABASE_SERVICE_ROLE_KEY: 'SECRET-ANON-abcdef',
      DATABASE_URL: 'postgresql://postgres:SECRET-DB-PASSWORD@host:6543/postgres',
      ADMIN_EMAIL: 'nope',
      ADMIN_PASSWORD: 'SECRET-SHORT',
      CSRF_SIGNING_SECRET: 'SECRET-CSRF',
      META_APP_ID: 'SECRET-META-ID',
      NEXT_PUBLIC_SOMETHING: 'SECRET-LEAKED',
      TRUSTED_PROXY_COUNT: 'SECRET-NOT-A-NUMBER',
    }

    const rendered = JSON.stringify(checkEnv(secrets))

    // Every finding above fired, so this is not passing by producing no output.
    expect(errors(checkEnv(secrets)).length).toBeGreaterThan(5)
    for (const value of Object.values(secrets)) {
      expect(rendered, `a finding contains the value of a variable`).not.toContain(value)
    }
  })

  test('lengths may be mentioned, since a length is not a secret', () => {
    const findings = checkEnv({ ...GOOD, CSRF_SIGNING_SECRET: 'abcdefgh' })
    expect(about(findings, 'CSRF_SIGNING_SECRET')[0]?.message).toContain('8 characters')
  })
})

describe('parsing the file', () => {
  test('reads keys, values, comments and blank lines', () => {
    expect(parseEnvFile([
      '# a comment',
      '',
      'PLAIN=value',
      'SPACED = spaced value ',
      '',
    ].join('\n'))).toEqual({ PLAIN: 'value', SPACED: 'spaced value' })
  })

  test('strips one pair of surrounding quotes and no more', () => {
    expect(parseEnvFile('A="quoted"\nB=\'single\'\nC="he said "hi""'))
      .toEqual({ A: 'quoted', B: 'single', C: 'he said "hi"' })
  })

  test('keeps everything after the first = , which connection strings need', () => {
    // postgresql://user:pass@host/db?options=a=b would be truncated by a naive split.
    expect(parseEnvFile('DATABASE_URL=postgresql://u:p@h/db?opt=a=b').DATABASE_URL)
      .toBe('postgresql://u:p@h/db?opt=a=b')
  })

  test('ignores an export prefix and lines with no =', () => {
    expect(parseEnvFile('export KEY=value\ngarbage line')).toEqual({ KEY: 'value' })
  })
})
