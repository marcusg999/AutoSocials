# PostDeck

A multi-tenant social media scheduling tool. **All five phases are built.**

What works today: sign in with a password and a TOTP code, connect Facebook Pages and
Instagram business accounts through Meta OAuth, write a post — with a writing assistant
if you want one — save it as a draft or schedule it to several accounts at once, watch
it on a calendar, move it or cancel it, and a worker publishes what is due. All times
are UTC.

| Phase | What it added | State |
|---|---|---|
| 1 | Security and tenancy spine: RLS, mandatory TOTP, Vault, audit log | Built |
| 2 | The Meta connector: OAuth, per-Page tokens, connect and disconnect | Built |
| 3 | Scheduling and publishing: the claim, the worker, composer and calendar | Built |
| 4 | Dashboard, drafts, editing and rescheduling | Built |
| 5 | The writing assistant | Built |

## Requirements

- Node.js 20 or newer
- A Supabase project — this is where auth (and therefore TOTP) lives, and there is no
  offline substitute for it
- A Postgres database the migration runner can reach directly over `DATABASE_URL`.
  Supabase's own database is the simplest choice: its connection string is under
  Project settings → Database.
- `psql` is not needed. `scripts/migrate.ts` connects with the `pg` driver.

## Running it locally

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

This applies every migration in order and seeds seven businesses, `BUSINESS_1` through
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

**5. Run the worker.**

Nothing is published by the web app. In a second terminal:

```bash
npm run publish:due
```

That claims everything due, publishes it, prints a one-line summary and exits. Run it
again whenever you want another pass — locally that is usually by hand; in production a
scheduler runs it (see the scheduler section below). If posts sit on the calendar past
their time, this is the thing that is not running, and the dashboard says so under
**Overdue**.

### The shortest path to seeing it work

Once the four steps above are done:

1. Sign in, and pick a business with the switcher at the bottom of the dashboard.
2. **Accounts** → *Connect facebook*. This needs a real Meta app (see the next section).
   Without one you can still use everything except publishing.
3. **Composer** → type something, tick an account, set a time a minute or two ahead,
   **Schedule**. Or **Save as draft** and come back to it from **Drafts**.
4. **Calendar** → the post is there, grouped under its UTC day, with *Move* and *Cancel*.
5. Wait for the time to pass, run `npm run publish:due`, and reload the calendar: the row
   is **Published**, with the id Meta gave it. If it failed, the provider's reason is on
   the row.

### If something is not working

| What you see | What it usually is |
|---|---|
| `ECONNREFUSED` from `npm run db:up` | Postgres is not running, or `DATABASE_URL` points somewhere else. `npm run db:ensure` will try to start one |
| Redirected to `/login` forever | The session cookie is not sticking. Check `APP_ORIGIN` matches the URL you are actually using, including the port |
| `Invalid CSRF token` on every form | `CSRF_SIGNING_SECRET` changed between rendering the form and submitting it, or is under 32 characters |
| Posts stay `Scheduled` after their time | Nothing is running `npm run publish:due` |
| No **Suggest** button in the composer | `ANTHROPIC_API_KEY` is not set in `.env.local` |
| "The assistant rejected the API key" | The key is wrong or revoked — check it at console.anthropic.com |
| A post fails with an image error | Meta fetches the image URL itself, so `localhost` and private addresses cannot work. The composer refuses the obvious ones up front |
| `npm run verify` fails only in `tests/db` | The database tests need a reachable Postgres. `verify` tries to start one first; if it could not, it says what it tried |

## Connecting a Meta account (Phase 2)

Register an app at developers.facebook.com, add **Facebook Login for Business**, and
set its valid OAuth redirect URIs to:

```
<APP_ORIGIN>/api/connectors/facebook/callback
<APP_ORIGIN>/api/connectors/instagram/callback
```

Put the app id and secret in `.env.local` as `META_APP_ID` and `META_APP_SECRET`.
The id is public by design — it appears in the authorization URL — but the secret is
server-only, is canaried by `npm run test:secrets`, and never reaches the browser.

Then sign in, pick a business, and use **Connect facebook** on the Accounts page. What
happens, and why each step is there:

1. The connect button is a **server action**, not a link, so it inherits the same
   guards as every other mutation: CSRF, an independently established `aal2` session,
   and an audit row written before anything else.
2. It mints an OAuth `state` that is **signed and bound to an httpOnly cookie**, and
   which carries the business id. Signing stops anyone minting a state we would
   accept; the cookie binding stops a state minted for one browser being replayed in
   another, which is how an attacker would otherwise attach *their* social account to
   your business. Carrying the business id stops the callback being aimed at a
   different tenant by editing a query parameter.
3. Meta redirects back to the callback, which is a **guarded** route — you must
   already be signed in with MFA to reach it. It verifies the state against the
   cookie, re-checks your membership of that business through row level security,
   then exchanges the code.
4. The exchange is three steps: code → short-lived user token → long-lived user token
   → **per-Page tokens**. Only the Page tokens are stored. A Page token is scoped to
   one account, so a leak costs one account rather than everything you can reach.
5. **Connecting Instagram asks each Page which Instagram account it owns**, and stores
   *that* id. Instagram shares the Meta app, the exchange and the Page token, but an
   Instagram business account is addressed by its own id — storing the Page id would
   connect cleanly and point at an account nothing can publish to. A Page with no
   Instagram account attached is skipped rather than connected.
6. Each token goes straight into Supabase Vault under a name derived from the account
   id. `social_accounts` stores only the non-secret reference; reading a credential
   back needs the account id, so the stored reference is not a lookup key.

**Disconnect** revokes at Meta, then clears local state and deletes the Vault secret —
in that order, and the local half happens even if revocation fails, because a token
you can no longer revoke is the one you most want to stop storing.

## Scheduling and publishing (Phase 3)

Write a post on **/dashboard/composer**, tick the accounts it should go to, pick a time,
and it appears on **/dashboard/calendar**. One post, one row per account, so a failure on
Instagram does not hide a success on Facebook.

**All times are UTC**, on the form and on the calendar, and every displayed time says so.
A `datetime-local` field carries no timezone at all, so reading it as anything else means
the same form submitted from two machines schedules two different moments.

Nothing is published by the web app. A worker does it:

```bash
npm run publish:due
```

That claims everything due, publishes it, prints a one-line summary, and exits. It is the
Railway entry point — run it on a schedule (every minute or two is sensible). It needs
`SUPABASE_SERVICE_ROLE_KEY`, because claiming and completing are `SECURITY DEFINER`
functions that only `service_role` can call. A post that fails is not a failed run: the
run reports it and moves on.

The claim is the part worth understanding, because publishing has exactly one failure that
cannot be undone — a post going out twice:

1. `app.claim_due_scheduled_posts` selects what is due `FOR UPDATE SKIP LOCKED` and marks
   it in the same statement, so two workers running at the same instant cannot take the
   same row.
2. It also writes a **lease** (`locked_until`, five minutes). A worker that dies releases
   its database lock immediately, but not its lease, so the next run leaves alone a row
   that may already have been published.
3. `attempts` increments when the row is claimed, not when it completes — otherwise a post
   that crashes the worker would retry forever.
4. `app.complete_scheduled_post` records the outcome. A success is terminal. A failure
   backs off (1, 3, 9, 27 minutes) and gives up after five attempts, leaving the provider's
   reason in `last_error` for the calendar to show.

Neither function can be called by a signed-in user. Their UPDATE grant on `scheduled_posts`
is narrowed to `scheduled_for` alone: you can move a post or cancel it, but declaring one
published is the worker's job.

## Drafts, editing and the dashboard (Phase 4)

The dashboard leads with what is **wrong**, because this app sends no notifications and
is the only place anything surfaces: accounts that are no longer connected, posts whose
time has passed while nothing published them, and posts that failed and gave up. Then
what is coming next.

A **draft** is a post with no scheduled rows — "scheduled" is a relationship, not a
flag, so drafts needed no new table. Saving one skips the per-platform rules on purpose:
a draft is allowed to be half-written, and the accounts it will go to have not been
chosen yet. Scheduling a draft promotes that same post rather than making a second one.

**Moving** a scheduled post is an UPDATE of `scheduled_for`, which is the only column
Phase 3 left a human on that table. Everything else about a post's lifecycle belongs to
the worker.

Editing stops when a post has actually gone out. `0015` adds a trigger that refuses to
change the body or status of a published post, and refuses to delete it — deleting would
cascade away the `scheduled_posts` row holding `published_at` and the provider's id,
which is the only local evidence it was ever published. A column grant could not express
this, because the fact that decides it lives on a different table. A post that merely
*failed* stays fully editable: nothing is live, so there is nothing to disagree with.

## The writing assistant (Phase 5)

Optional. Put an Anthropic API key in `.env.local` as `ANTHROPIC_API_KEY` and a
**Suggest** button appears in the composer; leave it unset and nothing changes anywhere
else in the app.

It reads the draft in front of you, plus an optional one-line steer ("shorter", "mention
the opening hours"), and proposes three alternatives. **Your draft is sent to Anthropic** —
that is the feature, and it is the only place in this app where your content leaves for a
third party. The image address is not sent; only the fact that an image is attached,
because that changes what a good caption looks like.

What it cannot do is the more useful half of the description. It cannot publish, cannot
schedule, cannot read another business's posts, and has no tools. Its entire output is
text on a page: **Use** saves a suggestion as a draft, and it still has to pass the same
platform rules and the same human pressing *Schedule* as anything you typed yourself.

Suggestions are stored rather than returned from the action, for two reasons. A server
action's return value travels in the flight payload, which the secret scan structurally
cannot read — so the one thing this feature produces would have gone through the one
channel nothing checks. And a suggestion is worth keeping: it cost money, it came from
your own draft, and `post_suggestions` records which model wrote it. That table has no
UPDATE grant at all, deliberately: it is the record of what the model said, and a row
you can edit in place cannot tell you whether the model wrote it or you did.

The system prompt lives in `lib/assistant/prompt.ts` where it can be read and reviewed in
a diff. Its most important line forbids inventing facts — no prices, hours or claims that
are not already in your draft — because that is the failure that does damage after a
human waves it through. The model is pinned to `claude-opus-5` at low effort: rewriting a
sentence in someone's voice is not a reasoning problem, and effort is the lever that
costs money.

## What you will see

| Route | What it does |
|---|---|
| `/login` | Email and password. Renders no data. |
| `/mfa/enroll` | TOTP enrolment. Shown until a verified factor exists. |
| `/mfa/verify` | TOTP challenge on later sign-ins. |
| `/dashboard` | Overview: counts, accounts needing attention, overdue, failed, what is next, and the business switcher. |
| `/dashboard/composer` | Write a post. Schedule it, save it as a draft, or ask the assistant for alternatives. |
| `/dashboard/drafts` | Saved but not scheduled. Edit or delete. |
| `/dashboard/calendar` | Everything scheduled, grouped by UTC day, with move and cancel. |
| `/dashboard/accounts` | Connect and disconnect social accounts. |
| `/api/connectors/[platform]/callback` | Where Meta returns the authorization code. Guarded: MFA session required. |

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

`test:secrets` also attaches a probe to **both the build and the server** and fails if a
tenant data read is observed — during the production build (a prerendered route's rows are
baked into the output and served to everyone from cache) or during an anonymous request.
The probe watches queries rather than connections: every write to a database socket, every
`fetch` or `node:http` call on a PostgREST path. Watching connections alone was not enough,
because a pooled connection is opened once and reused, so the read performs no connect.

That check exists because six consecutive review rounds defeated the static equivalent: the
question "does this page read tenant data" cannot be answered by inspecting which modules it
names, since a read added inside a module the page already ran changed nothing any static
model looked at.

The database tests need a Postgres server on `ADMIN_DATABASE_URL` (default
`postgres://postdeck:postdeck@127.0.0.1:5432/postgres`). They create and drop their own
scratch databases, and connect as a real `authenticated` role via `SET LOCAL ROLE` so that
row level security is genuinely enforced rather than simulated.

**`verify` and `test:db` start one for you.** `npm run db:ensure` runs first: if nothing is
listening it starts a stopped local cluster (`pg_ctlcluster` on Debian/Ubuntu, `brew
services` on macOS, or an existing `postdeck-postgres` container), waits for it, and
carries on. It reads cluster versions and service names out of the tools that know them
rather than guessing, and it never creates a database — a `docker run` would invent one
whose password and volume it chose for you.

It also tells the two failures apart. Nothing listening is a service to start; a server
that answers and rejects the credentials is a role or password problem, and it says so
instead of trying to start something that is already running. Run it on its own with
`npm run db:ensure`.

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
including `service_role`, and by revoking TRUNCATE from `anon`, `authenticated` and
`service_role` — TRUNCATE fires no row triggers and is not filtered by row level security,
so without that revoke the whole trail was removable in one statement by the role this
app's own server uses. The database owner (the role in `DATABASE_URL`, which runs the
migrations) still can; nothing inside the database can stop its own owner. Row changes are
recorded by database triggers rather than by application code, so a new mutation path
cannot forget to audit itself.

## Reading further

`BUILD_NOTES.md` documents every mistake made or narrowly avoided while building this —
100 numbered entries, each with the reproduction that proved it. Several are Postgres
behaviours worth knowing before you touch the migrations, such as
`ALTER DEFAULT PRIVILEGES IN SCHEMA x REVOKE ...` being a silent no-op, and views reading
straight through RLS unless created with `security_invoker = true`.
