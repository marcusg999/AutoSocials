/**
 * Reads .env.local and says what is wrong with it, before anything tries to use it.
 *
 * Setting this up means copying eight or nine values between a browser and a text
 * file, and every way of getting that wrong fails somewhere later and less
 * clearly: a service-role key that is actually the anon key fails when the Vault
 * is written, a pooler URL on the wrong port fails halfway through a migration, a
 * project URL that disagrees with the one the seed script used fails as "invalid
 * login" against a user that exists in a different project.
 *
 * The rule this file follows, which matters more than any check in it: IT NEVER
 * PRINTS A VALUE. A checker that echoes your keys into terminal scrollback — and
 * from there into a screenshot, a bug report, or a shared session — is a worse
 * leak than the mistake it is diagnosing. Findings name variables and say what is
 * wrong with them. Nothing else.
 *
 * It also makes no network calls. `db:up` and `seed:admin` are the real tests of
 * whether these values work; this is the ten-millisecond check for the mistakes
 * that are obvious from the text alone.
 */
import { existsSync, readFileSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'

const ROOT = process.cwd()
const TARGET = process.env.ENV_FILE ?? '.env.local'
const TEMPLATE = '.env.example'

export type Level = 'error' | 'warning' | 'note'
export type Finding = { level: Level; variable: string; message: string }

/**
 * A minimal .env parser: KEY=VALUE, one per line, # comments, optional quotes.
 *
 * Deliberately not a dependency. The file it reads is the one file in the project
 * that holds every secret at once, and the parser for it should be something you
 * can read in thirty seconds.
 */
export function parseEnvFile(text: string): Record<string, string> {
  const values: Record<string, string> = {}

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (line === '' || line.startsWith('#')) continue

    const separator = line.indexOf('=')
    if (separator === -1) continue

    const key = line.slice(0, separator).trim().replace(/^export\s+/, '')
    let value = line.slice(separator + 1).trim()

    // Strip one matching pair of surrounding quotes, and nothing else: a value
    // that legitimately contains a quote keeps it.
    if ((value.startsWith('"') && value.endsWith('"') && value.length >= 2)
      || (value.startsWith("'") && value.endsWith("'") && value.length >= 2)) {
      value = value.slice(1, -1)
    }

    if (key !== '') values[key] = value
  }

  return values
}

/** Variables the app cannot start without, whatever else is configured. */
const REQUIRED = [
  'NEXT_PUBLIC_SUPABASE_URL',
  'NEXT_PUBLIC_SUPABASE_ANON_KEY',
  'SUPABASE_SERVICE_ROLE_KEY',
  'DATABASE_URL',
  'SUPABASE_URL',
  'ADMIN_EMAIL',
  'ADMIN_PASSWORD',
  'CSRF_SIGNING_SECRET',
]

/** Optional, but must be configured as a set: one without the other is useless. */
const META_PAIR = ['META_APP_ID', 'META_APP_SECRET']

/** Still the value shipped in .env.example, i.e. not filled in yet. */
function isUnchanged(value: string, templateValue: string | undefined): boolean {
  return templateValue !== undefined && value === templateValue
}

/**
 * Looks like a stand-in rather than a real value.
 *
 * The `x`/`.` filler patterns match the WHOLE value rather than its start. An
 * earlier version anchored `xxx` to the beginning, which rejected any real secret
 * that happened to start with three x's — a false positive that blocks a correct
 * setup, which is the worse of the two errors a check like this can make.
 */
function looksLikePlaceholder(value: string): boolean {
  return /^(<.*>|your[-_]|replace|placeholder|example|changeme)/i.test(value)
    || /^[x.]{3,}$/i.test(value)
}

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === 'https:'
  } catch {
    return false
  }
}

/**
 * Everything wrong with a set of values, worst first.
 *
 * Pure, so the rules can be tested without a file on disk — and so the one
 * property that matters (no finding contains a value) can be asserted directly.
 */
export function checkEnv(
  actual: Record<string, string>,
  template: Record<string, string> = {},
): Finding[] {
  const findings: Finding[] = []
  const error = (variable: string, message: string) =>
    findings.push({ level: 'error', variable, message })
  const warn = (variable: string, message: string) =>
    findings.push({ level: 'warning', variable, message })
  const note = (variable: string, message: string) =>
    findings.push({ level: 'note', variable, message })

  // --- present and actually filled in -------------------------------------
  for (const name of REQUIRED) {
    const value = actual[name]
    if (value === undefined) {
      error(name, 'is missing')
    } else if (value === '') {
      error(name, 'is empty')
    } else if (isUnchanged(value, template[name]) || looksLikePlaceholder(value)) {
      error(name, 'is still the placeholder from .env.example')
    }
  }

  // --- the mistakes that fail late and confusingly -------------------------

  const projectUrl = actual.NEXT_PUBLIC_SUPABASE_URL
  const seedUrl = actual.SUPABASE_URL

  if (projectUrl && !looksLikePlaceholder(projectUrl) && !isHttpsUrl(projectUrl)) {
    error('NEXT_PUBLIC_SUPABASE_URL', 'is not an https URL')
  }

  // The quiet one. seed:admin writes the user through SUPABASE_URL while the app
  // signs in through NEXT_PUBLIC_SUPABASE_URL; if they differ, the account is
  // created in one project and looked for in another, and the only symptom is a
  // login that will not work.
  if (projectUrl && seedUrl && projectUrl !== seedUrl
    && !looksLikePlaceholder(projectUrl) && !looksLikePlaceholder(seedUrl)) {
    error('SUPABASE_URL',
      'does not match NEXT_PUBLIC_SUPABASE_URL — seed:admin would create the admin '
      + 'in one project while the app signs in to another')
  }

  const anon = actual.NEXT_PUBLIC_SUPABASE_ANON_KEY
  const serviceRole = actual.SUPABASE_SERVICE_ROLE_KEY

  // Pasting the same key twice is the classic slip, and it is silent: reads work,
  // then anything needing the Vault or the admin client fails much later.
  if (anon && serviceRole && anon === serviceRole) {
    error('SUPABASE_SERVICE_ROLE_KEY', 'is identical to the anon key — they are two different keys')
  }

  // --- DATABASE_URL, where most of the setup pain lives --------------------
  const database = actual.DATABASE_URL
  if (database && !looksLikePlaceholder(database)) {
    let parsed: URL | null = null
    try {
      parsed = new URL(database)
    } catch {
      error('DATABASE_URL', 'is not a valid connection URL')
    }

    if (parsed) {
      if (!/^postgres(ql)?:$/.test(parsed.protocol)) {
        error('DATABASE_URL', 'is not a postgres:// or postgresql:// URL')
      }
      if (parsed.password === '' ) {
        error('DATABASE_URL', 'has no password in it')
      } else if (/^\[.*\]$/.test(decodeURIComponent(parsed.password))) {
        error('DATABASE_URL', 'still has Supabase\'s [YOUR-PASSWORD] placeholder in it')
      }
      // The transaction pooler multiplexes statements across connections, which
      // breaks the session-level things migrations do.
      if (parsed.port === '6543') {
        error('DATABASE_URL',
          'points at the transaction pooler (port 6543) — migrations need the direct '
          + 'connection or the session pooler, both on 5432')
      }
      const isLocal = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(parsed.hostname)
      if (!isLocal && !/sslmode=/.test(database)) {
        warn('DATABASE_URL',
          'has no sslmode — append ?sslmode=require for a hosted database, since the '
          + 'migration runner takes SSL settings from the URL alone')
      }
    }
  }

  // --- the two length rules that are enforced elsewhere, checked early -----
  const csrf = actual.CSRF_SIGNING_SECRET
  if (csrf && !looksLikePlaceholder(csrf) && csrf.length < 32) {
    error('CSRF_SIGNING_SECRET',
      `is ${csrf.length} characters; it must be at least 32 (openssl rand -base64 48)`)
  }

  const adminPassword = actual.ADMIN_PASSWORD
  if (adminPassword && !looksLikePlaceholder(adminPassword) && adminPassword.length < 12) {
    error('ADMIN_PASSWORD',
      `is ${adminPassword.length} characters; seed:admin requires at least 12`)
  }

  const adminEmail = actual.ADMIN_EMAIL
  if (adminEmail && !looksLikePlaceholder(adminEmail) && !adminEmail.includes('@')) {
    error('ADMIN_EMAIL', 'is not an email address')
  }

  // --- settings that are wrong rather than missing -------------------------
  const origin = actual.APP_ORIGIN
  if (origin && !looksLikePlaceholder(origin)) {
    for (const entry of origin.split(',').map((value) => value.trim()).filter(Boolean)) {
      try {
        const parsed = new URL(entry)
        if (parsed.pathname !== '/' || parsed.search !== '') {
          warn('APP_ORIGIN', 'should be a bare origin like http://localhost:3000, with no path')
        }
      } catch {
        error('APP_ORIGIN', 'contains a value that is not a URL')
      }
    }
  }

  const proxies = actual.TRUSTED_PROXY_COUNT
  if (proxies !== undefined && proxies !== '' && !/^\d+$/.test(proxies)) {
    error('TRUSTED_PROXY_COUNT', 'must be a whole number (0 when nothing sits in front of the app)')
  }

  // --- optional features: configured as a set, or not at all ---------------
  const configuredMeta = META_PAIR.filter((name) => {
    const value = actual[name]
    return value !== undefined && value !== '' && !looksLikePlaceholder(value)
      && !isUnchanged(value, template[name])
  })
  if (configuredMeta.length === 1) {
    const missing = META_PAIR.find((name) => !configuredMeta.includes(name))!
    error(missing, 'is not set, but the other half of the Meta app is — set both or neither')
  } else if (configuredMeta.length === 0) {
    note('META_APP_ID', 'not set: you can use everything except connecting social accounts')
  }

  const assistant = actual.ANTHROPIC_API_KEY
  const assistantConfigured = assistant !== undefined && assistant !== ''
    && !looksLikePlaceholder(assistant) && !isUnchanged(assistant, template.ANTHROPIC_API_KEY)
  if (!assistantConfigured) {
    note('ANTHROPIC_API_KEY', 'not set: the composer simply will not show the Suggest button')
  }

  // --- the one that would be a real leak -----------------------------------
  for (const [name, value] of Object.entries(actual)) {
    if (!name.startsWith('NEXT_PUBLIC_')) continue
    if (name === 'NEXT_PUBLIC_SUPABASE_URL' || name === 'NEXT_PUBLIC_SUPABASE_ANON_KEY') continue
    error(name,
      'is a NEXT_PUBLIC_ variable this project does not know about — the prefix inlines '
      + 'its value into the browser bundle, so if it is a secret it is already public')
  }

  const order: Record<Level, number> = { error: 0, warning: 1, note: 2 }
  return findings.sort((a, b) => order[a.level] - order[b.level])
}

const LABEL: Record<Level, string> = { error: 'ERROR  ', warning: 'WARN   ', note: 'note   ' }

function main(): void {
  // ENV_FILE may be absolute (handy for checking a file outside the project);
  // join() would otherwise glue it onto the project root and report "not found".
  const path = isAbsolute(TARGET) ? TARGET : join(ROOT, TARGET)

  if (!existsSync(path)) {
    console.error(`${TARGET} not found. Start from the template:`)
    console.error(`  cp ${TEMPLATE} ${TARGET}`)
    process.exit(1)
  }

  const actual = parseEnvFile(readFileSync(path, 'utf8'))
  const template = existsSync(join(ROOT, TEMPLATE))
    ? parseEnvFile(readFileSync(join(ROOT, TEMPLATE), 'utf8'))
    : {}

  const findings = checkEnv(actual, template)
  const errors = findings.filter((finding) => finding.level === 'error')
  const warnings = findings.filter((finding) => finding.level === 'warning')

  console.log(`Checking ${TARGET} (${Object.keys(actual).length} values set)`)
  console.log('='.repeat(60))

  // Values are never printed — only names and verdicts. See the file header.
  for (const finding of findings) {
    console.log(`  ${LABEL[finding.level]}${finding.variable} ${finding.message}`)
  }
  if (findings.length === 0) console.log('  everything checks out')

  console.log('='.repeat(60))

  if (errors.length > 0) {
    console.error(`${errors.length} problem(s) to fix before npm run db:up will work.`)
    process.exit(1)
  }

  console.log(warnings.length > 0
    ? `No blocking problems, ${warnings.length} thing(s) worth a look.`
    : 'No problems found.')
  console.log('')
  console.log('This reads the file only — it makes no connection. `npm run db:up` and')
  console.log('`npm run seed:admin` are what actually prove these values work.')
}

// Guarded so the pure helpers above can be imported by a test without this running.
if (process.argv[1]?.endsWith('check-env.ts')) main()
