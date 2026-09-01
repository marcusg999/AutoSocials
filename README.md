# PostDeck

A multi-tenant social media scheduling tool. **Phase 1 of 5 is built: the security and
tenancy spine only.** There is no publishing, no scheduling, and no social-platform
code yet — those arrive in later phases.

What works today: an administrator can sign in with a password and a TOTP code, see the
businesses they belong to, and switch the active one. Everything else is a placeholder
that proves its own session and renders nothing.

## Requirements

- Node.js 20 or newer
- A Supabase project (for auth), plus a Postgres database you can reach directly
- `psql` is not required; the migration runner connects over `DATABASE_URL`

## Getting it running

**1. Install and configure.**

```bash
npm install
cp .env.example .env.local
```

Fill in `.env.local`. Every variable is commented in `.env.example` with what it is and
why it matters. Three are easy to get wrong:

- `CSRF_SIGNING_SECRET` — generate one with `openssl rand -base64 48`. At least 32 characters.
- `APP_ORIGIN` — the exact origin the app is served from. Required in production; the
  build refuses to start without it, because both the CSRF check and Next.js's own Server
  Action origin check compare against this rather than against request headers.
- `TRUSTED_PROXY_COUNT` — how many proxies sit in front of the app. Set it wrong and the
  audit log records a client address the client chose. Default `1`.

Never prefix a server-only variable with `NEXT_PUBLIC_` — the prefix inlines the value into
the browser bundle. `npm run test:secrets` enumerates the two variables that are meant to be
public and fails on any other `NEXT_PUBLIC_` name, whatever it is called; an earlier version
only matched secret-*sounding* names, and renaming `DATABASE_URL` to
`NEXT_PUBLIC_DATABASE_URL` passed it while serving a real connection string to the browser.

The `db:*` and `seed:admin` scripts read `.env.local` themselves (via Node's
`--env-file-if-exists`); `next dev|build|start` read it natively.

**2. Create the schema.**

```bash
npm run db:up
```

This applies eleven migrations in order and seeds seven businesses, `BUSINESS_1` through
`BUSINESS_7`. It is idempotent — running it twice is safe. `npm run db:down` rolls back,
and refuses to run while `audit_log` has rows unless you set
`ALLOW_DESTRUCTIVE_ROLLBACK=yes`, because the audit trail is append-only by design.

**3. Create the first administrator.**

```bash
npm run seed:admin
```

This reads `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`
from `.env.local` — set all four there rather than passing them on the command line, which
would put the service-role key in your shell history.

It creates the user through Supabase Auth and makes them an owner of all seven businesses.
It deliberately does **not** create an MFA factor — you enrol that yourself on first
sign-in, so the TOTP secret is never handled by a script.

**4. Run it.**

```bash
npm run dev
```

Then open http://localhost:3000. You will be redirected to `/login`. After the password
step you are sent to `/mfa/enroll`, where you scan a QR code with any authenticator app
and confirm one code. Nothing else in the app renders until that is done — not the
dashboard, not the placeholders, not a route handler.

## What you will see

| Route | What it does |
|---|---|
| `/login` | Email and password. Renders no data. |
| `/mfa/enroll` | TOTP enrolment. Shown until a verified factor exists. |
| `/mfa/verify` | TOTP challenge on later sign-ins. |
| `/dashboard` | Lists the businesses you are a member of, with an active-business switcher. |
| `/dashboard/composer` | Placeholder. Proves its own session, renders nothing. |
| `/dashboard/calendar` | Placeholder. |
| `/dashboard/accounts` | Placeholder. |

The dashboard list is filtered **by the database**, not by the page. If you remove your own
membership row, the list empties — the page has no idea which business belongs to whom.

## Verifying it

```bash
npm run verify
```

Runs build → typecheck → tests → secret scan, in that order. The order matters: one test
reads build output, and running it against a stale `.next` once produced a false green that
survived an entire review round.

Individual pieces:

```bash
npm run test          # everything
npm run test:db       # tenancy, MFA, audit, vault, migrations, hardening
npm run test:secrets  # builds with canary secrets and reads every route as a browser would
```

`test:secrets` also renders every route **anonymously with a probe attached to the socket
layer** and fails if the render opens a database connection or calls PostgREST. That check
exists because five consecutive review rounds defeated the static equivalent: the question
"does this page read tenant data" cannot be answered by inspecting which modules it names,
since a read added inside a module the page already ran changed nothing any static model
looked at.

The database tests need a Postgres server on `ADMIN_DATABASE_URL` (default
`postgres://postdeck:postdeck@127.0.0.1:5432/postgres`). They create and drop their own
scratch databases, and connect as a real `authenticated` role via `SET LOCAL ROLE` so that
row level security is genuinely enforced rather than simulated.

## How the security works, in short

**Tenancy.** Every table is behind row level security, enabled *and* forced. A row is
visible only to members of its business, decided through `business_members`. Each policy
carries a one-sentence plain-English comment above it in the migration.

**MFA.** Enforced in three independent layers: `proxy.ts` turns away anyone without a
complete `aal2` session; `requireMfaSession()` re-establishes identity from scratch inside
every page and every server action; and a `RESTRICTIVE` policy on every table means the
database itself returns zero rows to a password-only session. The middle layer exists
because Next.js routes Server Actions as POSTs to the page they live on, so a proxy matcher
that misses a path also misses its actions.

**Secrets.** Provider keys and per-account credentials live in Supabase Vault.
`social_accounts` stores only a derived reference, and `read_account_credential` takes an
account id and derives the secret name — so the stored reference is never a lookup key.

**Audit.** Append-only, enforced by triggers that refuse UPDATE and DELETE from every role
including `service_role`, and by revoking TRUNCATE from every role — TRUNCATE fires no row
triggers and is not filtered by row level security, so without that revoke the whole trail
was removable in one statement by the role this app's own server uses. Row changes are
recorded by database triggers rather than by application code, so a new mutation path
cannot forget to audit itself.

## Reading further

`BUILD_NOTES.md` documents every mistake made or narrowly avoided while building this —
100 numbered entries, each with the reproduction that proved it. Several are Postgres
behaviours worth knowing before you touch the migrations, such as
`ALTER DEFAULT PRIVILEGES IN SCHEMA x REVOKE ...` being a silent no-op, and views reading
straight through RLS unless created with `security_invoker = true`.
