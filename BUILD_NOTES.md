# PostDeck — Build Notes

Phase 1 of 5: the **security and tenancy spine**. No publishing, no scheduling logic,
no social-platform code. Later phases add the connector layer, the scheduler, the
dashboard/composer, and the AI assistant.

---

## Gotchas

Every mistake made or narrowly avoided in this phase. Kept because each one cost
real time or would have shipped a real hole.

### G1 — `middleware.ts` no longer exists in Next.js 16
Next.js 16 **renamed `middleware.ts` to `proxy.ts`** and the exported function from
`middleware` to `proxy`. Writing `middleware.ts` produces a file that is silently
never executed — the single worst failure mode for an auth gate, because the app
looks fine and is completely unguarded. Verified against the current Next.js 16.3.1
docs before writing a line.

### G2 — A proxy/middleware gate does not cover Server Actions
From the Next.js 16 docs, verbatim: *"Server Functions are not separate routes in
this chain. They are handled as POST requests to the route where they are used, so a
Proxy matcher that excludes a path will also skip Proxy coverage... Always verify
authentication and authorization inside each Server Function rather than relying on
Proxy alone."*

The brief asked for "middleware guards everything". Middleware alone **cannot** guard
everything. This is why the build uses three independent layers (see
`Defence in depth` below) instead of one.

### G3 — A `SECURITY DEFINER` function without a locked `search_path` is a privilege-escalation hole
Every helper in schema `app` is `SECURITY DEFINER` (it must be, to break RLS
recursion). Without `set search_path = ''`, a user who can create objects in a schema
earlier on the search path can shadow `auth.uid()` with their own function and the
definer-owned function will happily call it. Every such function here sets an empty
search_path and fully qualifies every name.

### G4 — The RLS recursion trap on `business_members`
The natural policy for `business_members` is "you can see it if you are a member" —
which requires reading `business_members`, which invokes the same policy, forever.
The fix is `app.is_member_of()`, a `SECURITY DEFINER` function that performs the
lookup outside RLS. Without it the first query against that table errors out.

### G5 — Postgres validates SQL function bodies at creation time
`app.is_member_of()` was first written into migration `0001`, which runs before the
`business_members` table exists in `0002`. A `language sql` function body is parsed
and validated when it is created, so the migration failed immediately. Moved all
membership helpers to `0005_rls_helpers.sql`, after the tables. (`language plpgsql`
bodies are *not* validated at creation — which is why the Vault wrappers, which
reference objects that only exist on hosted Supabase, are plpgsql.)

### G6 — An append-only audit table cannot carry `ON DELETE SET NULL` foreign keys
`audit_log.business_id` originally referenced `businesses(id) ON DELETE SET NULL`.
Deleting a business then tries to **UPDATE** the audit rows, which the append-only
trigger correctly refuses — so the rollback migration failed. Two problems in one:
the FK also meant deleting a business silently erased the audit history that
recorded the deletion. Fixed by making `actor_user_id` and `business_id` plain
`uuid` columns with no FK. **An audit trail has to outlive the thing it describes.**

### G7 — `scheduled_posts` has no `business_id`, and checking only `post_id` is not enough
`scheduled_posts` inherits its tenant from its parent post. The obvious policy checks
that you own the post — but the row *also* points at a `social_account_id`. Checking
only the post lets a member of Business B schedule their own post onto Business A's
connected Instagram account. The policy checks **both halves belong to the same
business**. There is a test for exactly this
(`tenancy.test.ts` → "cannot aim her own post at Alice's connected account").

### G8 — `RESTRICTIVE` vs `PERMISSIVE` policies
Permissive policies are OR'd together: adding one *widens* access. If the MFA gate
were permissive, any future policy added by a later phase would quietly bypass it.
The `mfa_required` policy on every table is `AS RESTRICTIVE`, so it is AND'd and can
never be widened. There is a test asserting the policy is restrictive on all six
tables, so a later phase cannot downgrade it unnoticed.

### G9 — A missing `aal` claim must fail closed
`app.has_completed_mfa()` reads `auth.jwt() ->> 'aal'`. If the claim is absent the
expression is `NULL`, and `NULL = 'aal2'` is `NULL`, which RLS treats as false — but
only by accident. It is written as `coalesce(auth.jwt() ->> 'aal', 'aal1') = 'aal2'`
so the intent is explicit, with a test for a JWT carrying no `aal` key at all.

### G10 — `ENABLE ROW LEVEL SECURITY` does not apply to the table owner
`ENABLE` alone leaves the owning role exempt. Every table also gets
`FORCE ROW LEVEL SECURITY`, so a mis-scoped connection or a migration running as the
owner cannot quietly read across tenants. A test asserts both flags on all six tables.

### G11 — RLS filters rows; it does not grant access
A table with RLS enabled and a perfect policy still returns "permission denied"
without a plain `GRANT`. Conversely, granting `authenticated` without RLS exposes
everything. Both halves are in `0006_rls_policies.sql`, next to each other, on
purpose. `anon` is granted nothing at all — a signed-out visitor cannot read a single
row from any table.

### G12 — The test harness must prove it is not cheating
DB tests connect as a superuser and then `SET LOCAL ROLE authenticated`. If that
`SET ROLE` silently failed, every isolation test would pass while proving nothing.
`mfa.test.ts` opens with a canary asserting `current_user = 'authenticated'` and that
the role is not a superuser. Without it the whole suite is decorative.

### G13 — `set search_path = ''` broke the Vault call chain
`app.store_account_credential` (search_path locked to empty) calls
`vault.create_secret`, which called `pgp_sym_encrypt` unqualified. The empty
search_path is inherited by the callee, so pgcrypto could not be found. Fixed by
schema-qualifying inside the test shim. Real hardening has real ergonomic costs.

### G14 — `@types/*` packages are not versioned in lockstep with their libraries
`@types/react-dom@19.2.8` does not exist (the runtime package is at 19.2.8; the types
are at 19.2.4). Guessing the types version from the library version failed the
install outright. Always resolve `@types` versions independently.

### G15 — The local Vault is a test double and must never be mistaken for the real one
Supabase Vault does not exist in plain Postgres, so `tests/db/supabase-shim.sql`
provides a stand-in built on pgcrypto with a hardcoded key. It is labelled in capitals
at the top of the file and lives under `tests/`, never in `supabase/migrations/`.
Migration `0008` creates the real `supabase_vault` extension and only warns if it is
unavailable. **The shim is never applied to a real database.**

### G16 — A helper function that returns an id is an enumeration oracle
The first version of the `scheduled_posts` policy used
`app.business_of_post(post_id)`, a `SECURITY DEFINER` function returning the owning
business id — and it was granted to `authenticated`. Because it runs outside RLS, any
signed-in user could hand it a post UUID and get back the id of the business that
owns it, learning about tenants they are not a member of. Caught in review before the
critic ran.

Replaced with two boolean helpers, `app.may_use_post()` and
`app.post_and_account_share_business()`, which answer only yes/no and so tell the
caller nothing they were not already entitled to know. The id-returning version still
exists as `app.business_of_post_for_audit()` for the audit trigger, granted to
**nobody** — the trigger runs as the function owner and can call it, while no session
can. Tests assert both the denial and the yes/no behaviour.

**The general rule: a `SECURITY DEFINER` helper should return a decision, not data.**

### G17 — `middleware-manifest.json` is empty on every Next 16 Turbopack build
Verifying that `proxy.ts` is actually registered by reading
`.next/server/middleware-manifest.json` gives `{"middleware": {}, "sortedMiddleware": []}`
and a 221-byte stub `middleware.js` — which looks exactly like "the auth gate was
silently ignored" (see G1). It is a false alarm: that file is a legacy webpack
artifact Turbopack no longer populates.

The authoritative artifact is **`.next/server/functions-config-manifest.json`**, which
lists the proxy under `/_middleware` with its runtime and compiled matcher regexp.
The build output line `ƒ Proxy (Middleware)` is the other reliable signal.

This matters because the natural way to check the most dangerous failure mode in the
build produces a convincing false positive. `tests/app/proxy-registration.test.ts`
asserts against the correct manifest so the check cannot drift back.

---

## Gotchas found by the adversarial review

An independent reviewer with no knowledge of the build attacked the database layer
against a live Postgres. The suite was 54/54 green at the time. It found four
issues the tests did not cover. Each now has a regression test in
`tests/db/hardening.test.ts`, named for the finding.

### G17 — CRITICAL: a client-writable pointer to a server-read secret
`social_accounts.encrypted_credential_ref` held the *name* of a Vault secret, and
`app.read_account_credential(name)` looked up whatever name it was handed. Both
looked fine in isolation. Together they meant a tenant could point their own row at
another tenant's secret — or at the platform-wide provider key — and the publisher
would faithfully use it. Every RLS policy passed, because the row being edited
genuinely belonged to the attacker.

The bar said "no secret reachable from a client session". That was *true* and
completely beside the point: the client never saw the secret, it just made the
trusted server use someone else's.

Two fixes, both needed:
- `encrypted_credential_ref` was removed from the UPDATE grant. `authenticated` now
  holds column-level UPDATE on the five harmless columns only.
- `read_account_credential` takes the **account id** and derives the secret name
  itself, so the stored reference is never a lookup key. Tampering with it buys
  nothing.

**The general rule: a pointer the client can write and the server dereferences with
its own privileges is a confused-deputy attack waiting to happen.**

### G18 — CRITICAL: `SECURITY DEFINER` plus a grant to `authenticated` is an RLS bypass
`app.write_audit()` was granted to `authenticated`. Being `SECURITY DEFINER`, it
never consults RLS — so a non-member at **aal1** could write permanent, undeletable
rows into any tenant's audit trail, with a forged action and a forged source IP.
The append-only triggers, which are correct, made the forgeries impossible to
remove.

The test that supposedly covered this only tried a direct `INSERT INTO audit_log`,
which a missing grant already blocked. It never called the function that was
actually granted.

Fixed by revoking it from `authenticated` entirely. App-level audit now goes through
the service-role client on our own server, which is also the only party that knows
the true client IP. `p_actor_user_id` exists for the one no-session case (a failed
login) and is always overridden by `auth.uid()` when a session exists, so it cannot
be used to impersonate.

**Root cause of both criticals, worth stating on its own: every `SECURITY DEFINER`
helper had been treated as internal plumbing and handed to the client role. The RLS
policies were audited carefully; the functions standing beside them were not.**

### G19 — CRITICAL: the test double was kinder than production
A real Supabase project runs, at bootstrap:

```sql
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
```

So **every table these migrations create is automatically granted ALL — including
TRUNCATE — to the signed-out `anon` role.** The migration's own comment claimed
"`anon` is granted nothing", and the test proving it passed — but only because
`supabase-shim.sql` omitted that one line of bootstrap. RLS does not filter TRUNCATE
and TRUNCATE fires no row triggers, so under the real privilege model a signed-out
role could have emptied every table, audit log included, leaving no trace.

Fixed by revoking everything from `anon` and `authenticated` at the top of
`0006_rls_policies.sql` before granting anything back, and by adding the default
privileges to the shim so the suite is measured against production reality.

**A test double that is more permissive than production certifies nothing. If a
harness models the happy path of your infrastructure, it will hide exactly the
class of bug that infrastructure causes.**

### G20 — A legible policy is not a correct policy
The reviewer's sharpest observation. The policy reading *"you may edit a social
account only if you are a member of its business"* is accurate, clearly written,
passes the one-sentence test — and concealed both G17 and a role bug. Quality bar
criterion 6 (readability) passed throughout while criteria 1–4 were failing.

**Readability makes a policy auditable. It does not make it right, and it should
never be mistaken for evidence.**

### G21 — The `role` column was decorative
Every `posts` and `social_accounts` policy checked `is_member_of` and never
`has_role_in`, so a `viewer` could delete every post and disconnect every account.
`business_members` and `businesses` used roles correctly; the two tables holding the
actual product data ignored them. No test had ever authenticated as a viewer.

The brief scoped roles as "future", but shipping a role named `viewer` that has full
destructive authority is a trap rather than a deferral, so write access on both
tables now requires `owner` or `manager`. This is a small, deliberate step beyond
the brief.

### G22 — A foreign key is an existence oracle
`posts.created_by` referenced `auth.users` with no policy check, so inserting a post
into your own business with someone else's user id returned a foreign-key error for
a *non-existent* user and succeeded for a *real* one — a platform-wide "does this
account exist?" probe, plus authorship forgery. Now `created_by` must equal
`auth.uid()`, so the policy rejects both cases identically and the foreign key is
never reached.

### G23 — Cascade deletes orphan their own audit rows
Deleting a post cascades to `scheduled_posts`. The audit trigger resolved that
child's tenant by looking up its parent post — which, on a cascade, is already gone.
The result was an audit row with a null `business_id`, readable by nobody. Fixed by
denormalising `business_id` onto `scheduled_posts`, which also simplified three of
its RLS policies. A small, flagged deviation from the column list in the brief.

### G24 — A rollback that is safe on an empty database is not a safe rollback
`migrations.test.ts` asserted "up, down and up again run clean" against an *empty*
database — certifying precisely the case that cannot lose data. The seed rollback
deleted businesses by name, and `businesses` cascades to members, posts and
accounts, so running it against a live database would silently destroy real customer
work. It now skips any business that has members, posts or connected accounts, and
the test populates a database first.

### G25 — `authenticated` could punch holes in the audit log's id sequence
`grant usage on all sequences ... to authenticated` included `audit_log_id_seq`.
Any user could burn ids, and sequence increments survive rollback — so gaps could be
manufactured at will. In an append-only log a gap is supposed to mean tampering. No
sequence is granted to anyone now.

---

## Gotchas found by the second adversarial review

A second reviewer, fresh context, attacked the whole stack after round 1's fixes.
It failed criterion 4 outright and found that round 1 had fixed the *instances* it
was shown rather than the *classes* they belonged to. That judgement was correct and
is the most useful thing either review produced.

Every fix below is now pinned by a **class test** — one that enumerates every
member of the category rather than checking the specific case that was reported.

### G26 — The same column, a different verb
Round 1 removed `encrypted_credential_ref` from the UPDATE grant. The INSERT grant
was still table-wide, so a **new** row could be created pointing at another tenant's
Vault secret — the identical attack through the other verb. The regression test was
titled *"not writable by a signed-in user at all"* and only exercised UPDATE: the
test name asserted more than the test did.

Both grants are now column-scoped, and the class test asks Postgres directly whether
the column is writable by `authenticated` through INSERT *or* UPDATE.

**If a test's name is broader than its body, the name is a lie that will be believed.**

### G27 — CSRF: two half-measures that cancelled out
Two defects that were individually survivable and together fatal:

- **The origin check consulted the request.** It compared `Origin` against
  `x-forwarded-host` — a header the client sends. The rule was effectively "Origin
  must match whatever host this request claims to be for", which any attacker
  satisfies by sending both. Now compared against a configured `APP_ORIGIN`
  allowlist, which fails closed if unset in production. `next.config.ts` names the
  same origins for Next's own Server Action check, which had the same weakness.
- **The token was unsigned.** `assertCsrf` only checked cookie == field, so any
  value an attacker could plant satisfied it, being both halves. The token is now
  `nonce.expiry.HMAC`, so the server verifies it minted it; an unsigned cookie is
  *replaced* rather than trusted, and the token is rotated at sign-in and cleared at
  sign-out.

The tests had two describe blocks, `'the token itself'` and `'the cookie'` — and
never once called `assertCsrf`. **The checking code, not the token, is where CSRF
bugs live.**

### G28 — The one function nobody revoked
Every function in schema `app` carried an explicit `revoke ... from public` except
`app.audit_row_change()`, which was left PUBLIC-executable. Being SECURITY DEFINER,
a user could attach it to a temp table of their own and forge permanent, undeletable
rows into any tenant's audit trail.

A uniform pattern applied by hand will eventually miss one member. The class test now
enumerates `pg_proc` for schema `app` and fails if **any** function has a null ACL.

### G29 — A one-time revoke against a standing rule
Round 1 revoked `anon`'s privileges on the tables that existed *at that moment*. The
Supabase default-privilege rule that granted them was still in force, so the very
next migration would create a table granted to `anon` all over again — TRUNCATE
included. `alter default privileges ... revoke all` now cancels the rule itself, and
the class test creates a table and checks `anon` gets nothing.

**Revoking a privilege is not the same as revoking the rule that grants it.**

### G30 — The audit log had no second layer
The sharpest finding. Everything else in this design has depth: tenancy has RLS *and*
FORCE *and* column grants; auth has the proxy *and* `requireMfaSession()` *and* a
restrictive policy. The audit log had none — append-only so a bad row is permanent,
best-effort so a good row was optional, forgeable via G28, and blind to the one
operation that touches a real credential.

Fixed on four fronts: `recordAuditOrThrow` makes the row mandatory for
authentication events and business switching (a dropped row there is exactly the
event an attacker wants unlogged); `store_account_credential` validates its account
id and writes an explicit audit row, distinguishing a first store from a rotation;
`audit_row_change` is revoked from PUBLIC; and the code-exchange route is gone.

### G31 — Rotating a credential recorded that nothing changed
`store_account_credential` relied on its `UPDATE social_accounts` firing the row
trigger. Rotating a credential writes the same reference back, so no column changed
and the audit row read `changed_columns: []` — a permanent record saying nothing
happened, for the most sensitive operation in the system. Worse, storing against an
unknown account id updated no row at all, so a secret entered the Vault with **no**
audit row. It now validates the id and audits explicitly.

### G32 — Deleting an endpoint beats hardening it
`/auth/callback` exchanged an attacker-supplied `code` query parameter for a session,
with no `state` validation, no audit row, and — by necessity — placement outside every
auth guard. Phase 1 signs in with email and password only; nothing linked to it.

It was deleted rather than fixed. A test now asserts no route handler calls
`exchangeCodeForSession`, so it cannot reappear without a deliberate decision.
**The most reliable way to secure an endpoint you are not using is not to ship it.**

### G33 — A GET that mutates
Rendering the MFA enrol page unenrolled and recreated the user's pending factor —
two writes on a plain GET, with no CSRF token. `SameSite=Lax` sends session cookies
on top-level cross-site navigation, so any website could churn a victim's pending
enrolment by linking to the page. The page now starts an enrolment only when there
is not one already, and "start over" is a CSRF-protected POST.

### G34 — The action was weaker than the page it belonged to
`app/mfa/enroll/page.tsx` redirected a user who already had a verified factor;
`confirmEnrollmentAction` did not, and validated the submitted factor against
`factors.all`, which includes unverified ones. So the *page* refused "enrol a second
factor while holding an unchallenged first one" and the *action* did not — the
textbook MFA bypass, stopped only by GoTrue's own policy. A guard on the page that is
missing from its action is not a guard.

### G35 — The class of "the tests match the fixes"
Stated plainly because it is the lesson, not an incident: after round 1 the suite was
137 green tests that covered the RLS matrix thoroughly and the application security
layer barely at all. No test imported `lib/security/session.ts`, any server action,
or checked a single function ACL. Tests written in response to findings will always
be shaped like those findings.

The suite now includes structural tests that enumerate rather than sample: every
server action must call `assertCsrf` first and establish its own session; every page
must call `requireMfaSession()` or appear on a short, justified list whose members
are separately checked for making no database call at all. These catch the action
somebody adds next year, which no hand-written per-route test can.

---

## Gotchas found by the third adversarial review

Round 3 verified each earlier fix by attacking it — ten of twelve held. Its central
result was harsher than any individual finding: **the verification layer was weaker
than the thing it verified, and weakest exactly where rounds 1 and 2 had declared
victory.** Three of the four "class" tests, and the secret scanner, asserted a
*proxy* for their property rather than the property, and all four were made green
while the property was false.

### G36 — `proacl is not null` is not "PUBLIC cannot execute"
The class test guarding against a PUBLIC-executable `SECURITY DEFINER` function
checked that the function had *some* ACL. But `proacl` is null only when no grant
has ever been issued; the moment any grant exists Postgres materialises the ACL
**including the default PUBLIC entry**. A function that was both granted and
PUBLIC-executable sailed through. Verified:

```
proname=future_helper | my_class_test_passes(proacl is not null)=true | PUBLIC_CAN_ACTUALLY_EXECUTE=true
```

Now asks `has_function_privilege('public', p.oid, 'EXECUTE')`, which cannot be
satisfied by anything except the fact itself.

### G37 — `ALTER DEFAULT PRIVILEGES IN SCHEMA x REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` is a silent no-op
The most surprising thing found in three rounds. Round 2 cancelled the default
privilege for tables and sequences; functions were missed, so the next migration's
helper was PUBLIC-executable again. The obvious fix did not work — and did not
complain:

```
alter default privileges in schema app revoke execute on functions from public;   -- "ALTER DEFAULT PRIVILEGES"
create function app.probe1() ...;
probe1 PUBLIC-exec = true      <-- unchanged, and no pg_default_acl row was written

alter default privileges revoke execute on functions from public;                 -- no IN SCHEMA
create function app.probe2() ...;
probe2 PUBLIC-exec = false     <-- works
```

Postgres's built-in `PUBLIC EXECUTE` on functions is a global default, so a
schema-scoped revoke has nothing to subtract and is dropped. Only the unqualified
form cancels it. **A statement that reports success and stores nothing is worse
than one that errors.**

### G38 — `export const x = async () => {}` is a server action too
The structural test asserting that every server action checks CSRF and establishes
its own session matched only `export async function`. An action declared as an
arrow function was invisible to every check in the file — which is precisely the
"someone adds one next year and forgets" case the file exists to catch. Adding an
unguarded `nukeAction` left the suite at **24/24 green**.

It now matches all three declaration forms, and — more importantly — separately
asserts that the set of recognised actions equals the set of *all* exported
bindings, so a form nobody anticipated fails loudly instead of being skipped
silently. Re-verified: the same unguarded action now fails two tests.

### G39 — The secret scanner could not see a single application page
`scripts/check-no-secrets.ts` grepped `.next/static` plus any prerendered output.
Every page in this app sets `dynamic = 'force-dynamic'`, so **nothing is
prerendered** — `.next/server/app` held only `_not-found` and `_global-error` — and
`.next/static` can never contain a value serialized at *request* time. The scan was
structurally blind to 100% of the app.

Proven by planting the leak it exists to catch: a client component receiving
`process.env.SUPABASE_SERVICE_ROLE_KEY` as a prop. The check printed
`All 6 secret-handling checks passed`, exit 0, while the canary was visible twice
in `curl` output — once in the HTML, once in the RSC flight payload.

The scanner now builds with canaries, **starts the app**, enumerates every route
from Next's own manifest, and reads each one as HTML and as an RSC flight response,
headers included. Re-verified: the same leak now fails the check and exits 1.

The blind spot was getting *less* likely to fire as the app grew — Phase 1 has one
client component, and Phase 2 is when they arrive.

### G40 — "The JWT always wins" never fired in production
`app.write_audit` preferred `auth.uid()` over the caller-supplied actor, and
`lib/audit.ts` cited that as a database-side backstop against impersonation. But a
Supabase **service-role** JWT carries no `sub` claim, and the service-role client is
the only caller — so `auth.uid()` is null on every call the app actually makes and
the precedence rule never competed. The comment was false in the only configuration
that ships.

Now: a conflicting actor while a user JWT is present is a hard error rather than a
silent override, and every row records `metadata.actor_source` as `jwt` or
`caller`, so which one applied is a visible fact in the row instead of an
assumption about a backstop.

### G41 — A policy that enforced the opposite of its own comment
`posts_update_own_business` said *"it must stay in the same business and keep its
author"* and required `created_by = auth.uid()` on the **new** row — so a manager
editing a colleague's post could not leave the author alone; the only route the
policy left open was reassigning authorship to themselves. Collaborative editing
was impossible and silent authorship theft was mandatory.

`created_by` is now outside the UPDATE grant entirely and pinned by a
`BEFORE UPDATE` trigger, so it cannot change by any route including a worker or a
migration. Three tests cover it, one of which is specifically "a manager can edit a
colleague's post without stealing authorship".

This was also a criterion-6 failure, and the sharpest illustration of G20: **a
one-sentence explanation that is false is worse than none, because the reader stops
reading the policy.**

### G42 — `X-Forwarded-For[0]` is the client's own claim
The audit IP took the first entry, with a comment explaining that later entries were
appended by proxies "we do not control". That is backwards: an appending ingress
(nginx `proxy_add_x_forwarded_for`, ALB, HAProxy) produces
`<whatever the client sent>, <the address the proxy actually saw>`. Every IP in the
audit log was therefore attacker-chosen — including on the failed-login rows whose
whole purpose is spotting credential stuffing. Now read from the end, offset by a
configured `TRUSTED_PROXY_COUNT`.

### G43 — An aal2 session outlived the factor that produced it
`resolveSessionState` trusted the `aal` claim alone. A JWT stamped `aal2` stays
valid for its whole lifetime, so a session remained fully privileged after its TOTP
factor had been deleted — "password plus TOTP" with no TOTP left in existence. The
factor list was already being fetched on the previous line; it is now checked.

### G44 — Audit rows written after the mutation they describe
`recordAuditOrThrow` was called *after* `signInWithPassword` and after
`mfa.verify()`. Throwing does not undo a session: the user was signed in (or
upgraded to aal2), the request 500'd, and no row existed. Anyone able to make the
audit write fail could authenticate without a trace — the exact event the
must-succeed path was introduced to guarantee. An attempt row is now written
*before* each of those mutations, so the trail can never be shorter than reality.
The same reordering applies to discarding an MFA factor.

### G45 — A signed CSRF token still is not *your* token
Round 2 signed the token so the server could prove it minted it. Round 3 pointed out
that this does not prove it minted it **for you**: a legitimate user could read
their own cookie value and replay it as anyone else, given a cookie-write primitive.
The token is now signed over the session subject as well, so one user's valid token
fails for another, and a pre-login token fails after login. In production the cookie
also carries the `__Host-` prefix, which browsers refuse to let any subdomain write
— closing the planting step the attack depends on.

### G46 — An extension-based matcher exempts routes that do not exist yet
The proxy matcher excluded anything ending `.txt` or `.xml`. Harmless in Phase 1,
and an unguarded, header-less hole the day a later phase adds an export, a feed or
a sitemap route handler. Exclusions are now by location (`_next/static`,
`_next/image`, `favicon.ico`), never by extension.

### G47 — Unbounded, unauthenticated, permanently unremovable audit writes
`signInAction` stored the submitted email verbatim on failure, with no length bound
(`<input type="email">` is client-side only) and no rate limiting. A 500 KB value
was accepted, and the append-only triggers mean nothing — not the owner, not
`service_role` — can ever remove it. Capped at the RFC maximum of 320 characters.
Rate limiting is still absent and is listed below as a known limitation.

---

## Gotchas found by the fourth adversarial review

Round 4 opened by correcting a claim in the handover: **the suite was red, not
green.** 196 of 197 passed. That correction is the most useful thing in this
section, and the cause is worth more than the symptom.

### G48 — A test that reads build output will report on code that no longer exists
`tests/app/proxy-registration.test.ts` reads
`.next/server/functions-config-manifest.json`. The verification run that declared
"197 tests pass" ran vitest **before** `scripts/check-no-secrets.ts` rebuilt
`.next`, so it checked a manifest built from source that had since changed. The
matcher change contradicted an assertion in that file and the contradiction was
invisible for a whole round.

Two fixes, because either alone would leave the trap: the test now compares
`proxy.ts`'s mtime against the manifest's and refuses to run against a stale build,
and `npm run verify` sequences build → typecheck → test → secret scan so the
question cannot arise. **Any check that reads a build artifact is really a check on
"when did you last build", and will lie if asked out of order.**

### G49 — Round 3 fixed the precision of every check and none of their scope
The round's central result. Each rebuilt check used a better *predicate* on a
*narrower domain* than the property it claimed:

| Check | Precision fixed | Scope still wrong |
|---|---|---|
| Function ACLs | `has_function_privilege` not `proacl` | schema `app` only, PUBLIC only |
| Server actions | three declaration forms | `.ts` only, no `route.ts`, `export *` invisible |
| Secret scan | live responses not build output | unauthenticated only |

Every one had a demonstrated instance where the check passed and the property was
false. All are now fixed **and re-verified by replaying the exact bypass**, which is
the only way to know a test tests anything.

### G50 — The secret scan measured redirects and called them pages
Every route but `/login` is behind the auth gate, so fetching them unauthenticated
returned a 307 whose body is the six bytes `/login`. The scan reported "16 served
responses" while inspecting one page, and passed with the service-role key rendered
on the dashboard.

Three changes: a tightly-fenced scan mode (`lib/security/scan-mode.ts`) lets the
scanner render authenticated pages; **any response that is not a 200 now fails the
scan as incomplete** rather than being counted; and routes that genuinely cannot
render without a live Supabase project are named in the output as unscanned. That
last point matters — the honest result is "12 responses scanned, 4 could not be",
not a green tick over a silent gap. Re-verified: the leak on a guarded page is now
caught in both the HTML and the RSC flight payload.

### G51 — Three kinds of server entry point the guard test could not see
Each was added to the tree and the suite stayed at 29/29 green:
- **`route.ts` handlers** were collected and then grepped only for
  `exchangeCodeForSession`. An unguarded `GET /dashboard/export` returning
  `select * from businesses` passed.
- **`'use server'` in a `.tsx` file** — the collector filtered `.endsWith('.ts')`.
  Actions colocated with a component are idiomatic Next and were invisible.
- **`export * from './hidden'`** — neither the "recognised actions" set nor the
  "all exports" set can see through it, so the equality assertion added in round 3
  was satisfied by both sides being equally blind.

All three now fail. `export *` inside a `'use server'` module is banned outright,
because there is no way to follow it with a regex and a check that cannot see
something must not pretend otherwise.

### G52 — A guard satisfied by a comment, and one that accepts aal1
The guard assertions matched raw source text, so `// await assertCsrf(formData)`
passed. Comments are now stripped before matching.

Worse: the session assertion accepted `requireSignedInUserOrThrow`, which by design
returns a **password-only, aal1** session. Any action could satisfy criterion 3 with
a guard that does not enforce criterion 3. That is now allowed by path — inside
`app/mfa/**`, where aal2 does not exist yet, and `signOutAction`, because a user who
cannot complete MFA must still be able to leave — and everywhere else
`requireMfaSessionOrThrow` is required.

### G53 — `pgcrypto` put 36 anon-callable functions into `public`
`create extension pgcrypto` with no schema clause lands in `public`, which PostgREST
exposes as RPC, and every function in it was callable by the signed-out `anon` role.
`public.crypt()` at bcrypt cost 14 takes about a second of database CPU per call;
the cost parameter goes to 31.

Nothing needed it — `gen_random_uuid()` has been core since PostgreSQL 13, and only
the test shim's stand-in Vault uses pgcrypto. The extension is gone from the
migrations entirely, and the shim now installs it into an `extensions` schema the
way Supabase does, so the test database is no longer friendlier than production.
Count of public functions reachable by `anon`: 36 → **0**.

### G54 — The default-privilege revoke was role-scoped and broke `CREATE EXTENSION`
The unqualified form from round 3 works, but two things were missed. It is recorded
against the role that runs it, so a function created by any other role is unprotected
— that is now the class test's job, and the test checks `anon`, `authenticated` and
`PUBLIC`, not just `PUBLIC`. And because it is unqualified it applies to every
schema, so any extension installed into `public` produces a type whose operators
raise `permission denied` for `authenticated`; verified with `citext`, where
`'ABC'::citext = 'abc'::citext` failed outright.

Both are addressed in `0010_lock_down_functions.sql`, which revokes explicitly
across schema `app` after every function exists, re-grants exactly the five a
browser session may call, and establishes the `extensions` schema convention so
future extensions keep working.

### G55 — `business_members` was the same FK oracle, one table over
Round 3 closed the `posts.created_by` existence oracle and did not generalise it.
`business_members.user_id` is a foreign key into `auth.users` and nothing pinned it:
a non-existent id raised a foreign-key error, a real one succeeded, so an owner could
probe the whole platform for account existence — and silently attach a real person
to a business they had never heard of, with role `owner`.

Phase 1 has a single administrator and manages membership from the seed script under
`service_role`, so the fix is that the application has no write access to the table
at all. **The narrowest correct scope is usually the fix.**

### G56 — A caller-controlled header could make the audit write throw
`clientIp()` filtered with a character class, so `....` and `::::` passed it and then
raised `invalid input syntax for type inet` *inside* `app.write_audit`. Combined with
`switchBusinessAction` writing its cookie before auditing, a chosen header made the
mutation succeed and its audit row throw. The address is now parsed properly and an
unparseable one is recorded as null, and the audit row is written before the cookie.

### G57 — Auditing an audit log does not terminate
While writing the class test asserting every business-scoped table has an audit
trigger, `audit_log` failed it — it carries a `business_id` and is deliberately not
audited, because a trigger writing an audit row for every audit row recurses forever.
Excluded with the reason stated, rather than by quietly narrowing the query.

---

## Gotchas found by the fifth adversarial review

Round 5 answered round 4's sign-off condition — *does the scanner read authenticated
pages, and does the guard test cover `route.ts`, `.tsx` and `export *`?* — with
"literally true, materially false". It then got a real service-role key into a
browser three ways with the scanner exiting 0, and shipped four unguarded server-side
entry points with the whole suite green.

### G58 — The scanner reported its best-ever coverage while reading a different server
The worst finding in five rounds, and the third appearance of the same bug wearing
new clothes. `spawn('next start')`'s exit code was never checked and the readiness
probe only proved that *something* answered on the port. With an unrelated process
squatting on 3987:

```
$ node squat.mjs &          # 40-byte dummy server
$ npx tsx scripts/check-no-secrets.ts
  PASS  no server-only secret appears in any of 16 served responses or 12 static chunks
All 8 secret-handling checks passed.        EXIT=0
```

**Sixteen responses "scanned" — more than the honest run's twelve — while inspecting
a 40-byte string sixteen times.** Round 3's note about this file said it "reported 16
served responses scanned while actually inspecting one page". This is the same
sentence with *zero* pages.

Fixed with a handshake the scanner cannot be fooled about: the proxy answers a scan
request with `x-postdeck-scan-ack`, derived from that run's token, so only a process
holding the token can produce it. The child's stderr and exit code are captured and
reported. The server binds loopback only.

### G59 — Every dynamic route was skipped, and not even named
`if (route.includes('[')) continue`. A page at `/dashboard/[businessId]` rendering
the service-role key returned 200 with the key in the HTML, and the scan reported
8 routes, 12 responses, all clear. Unlike the excused routes it was not listed
anywhere in the output.

Phase 2 is almost entirely dynamic segments, so the blind spot was aimed exactly at
the code that does not exist yet. Segments are now filled with placeholder UUIDs and
scanned. A placeholder that 404s is a fine outcome; a route nobody looked at is not.

### G60 — The routes that render tenant data were the ones excused
`NEEDS_LIVE_DATABASE = ['/dashboard', '/', '/mfa/enroll', '/mfa/verify']` sent
unscannable routes to `console.log` rather than `fail()`. Those four were the only
routes that render anything; the remaining coverage was `/login` and three pages
whose entire content is "Coming in a later phase." A leak planted on `/dashboard`
passed.

The allowlist is gone. Any route that cannot be inspected now fails the scan. To
make that achievable, the scanner starts a small stand-in for the Supabase REST and
Auth endpoints so authenticated pages actually render — the question a leak check
asks is whether the *server's own* secrets reach the browser, not what the rows
contain. A 200 that is really Next's error boundary is no longer counted either.

**An exclusion list on a security check is a list of the places you are not
checking. Ours had drifted to contain everything that mattered.**

### G61 — Verdict on the scan-mode bypass
Round 5's judgement was blunt and right: as it stood, a permanent auth-bypass code
path was being carried in the production bundle to gain coverage of `/login` and
three placeholder pages. Not worth it.

It is worth it now, because with the Supabase stub it delivers every route with no
allowlist — which is the only reason to accept it. Its fences were attacked
individually and all held except one: `isScanModeSafeHere` pattern-matched the raw
`APP_ORIGIN` string, and `http://localhost:3000@evil.com` has hostname `evil.com`
(`localhost:3000` is userinfo). It now parses the URL and compares `.hostname`, the
way `csrf.ts` already did.

Every production-shaped misconfiguration fails **closed** — a throw inside `proxy()`
is a 500 on every request, not an open door — and the header appears in zero client
chunks.

### G62 — `'use server'` is legal anywhere, and the guard test walked two directories
`walk('app').concat(walk('lib'))`. An unguarded action in `components/danger.ts` was
invisible; the suite stayed green. It now walks the project root minus
`node_modules`, `.next`, `tests`, `supabase` and `scripts`.

### G63 — An anonymous default export hides everything declared inside it
`export default async function () {` binds no name, so the "recognised actions" and
"all exports" sets were **both empty** and the equality guard added in round 4 was
satisfied by two empty lists. An inline `'use server'` action inside such a
component — no CSRF, no session check, deleting businesses — passed 39/39.

The save was thinner than that: with `export const dynamic = 'force-dynamic'`
present the equality guard happened to fire on `dynamic`, an unrelated line. Remove
one line and it went green. **A test held up by a coincidence is not held up.**

Anonymous default exports are now banned outright, and inline `'use server'` blocks
are found and checked where they are declared.

### G64 — `export const POST = async` is not `export async function POST`
The route-handler CSRF requirement was keyed on the second form, so the first
matched nothing, `methods` came back empty, and the requirement never applied.
Both forms are matched now — and each method is checked against **its own body**,
because the previous file-wide match let a guarded `GET` vouch for an unguarded
`POST` sitting beside it.

### G65 — Two class tests that could not see a new table
- The audit-trigger test filtered `nspname = 'public'` and detected business scope
  by a column literally named `business_id`. A table in schema `app`, or one whose
  column is `tenant_id`, was cross-tenant readable and writable with zero audit rows
  while the suite stayed green. Scope is now detected by **foreign key to
  `businesses(id)`** across both schemas.
- The "RLS enabled and forced" test asserted against a hardcoded list of six tables
  and `expect(rowCount).toBe(6)` — it cannot notice a seventh, by construction. It is
  now asserted by exclusion: every table in `public` and `app`, except the migration
  ledger, must have RLS enabled and forced.

**A check that enumerates what exists cannot catch what gets added. Assert by
exclusion.**

### G66 — A rollback that did the opposite of its own comment
`0010_lock_down_functions.down.sql` opened with
`alter default privileges grant execute on functions to public;` directly above a
comment reading *"It does NOT restore PUBLIC execute: that was never wanted."*
Measured after `down`, a newly created function was PUBLIC- and anon-executable.
Undoing a lockdown should never mean unlocking.

---

## Gotchas found by self-review after round 6 was cut short

Round 6 hit a session limit and terminated before producing any findings. Its last
recorded step was beginning to attack the database class tests, so those attacks
were run directly instead. **This section is self-review, not an independent
adversarial pass, and is weaker evidence than the sections above.** The findings are
real regardless — each was demonstrated against a live database.

### G67 — A view reads straight through row level security
The largest hole found in the schema, and one no amount of policy work would have
closed. A Postgres view executes with the privileges of its **owner** unless
`security_invoker = true`, which is off by default. So a convenience view over
`posts` hands every tenant every row while all the underlying policies remain
perfectly intact:

```
tenant B sees via view:    {"secret": "TENANT_A_PRIVATE"}
tenant B sees via matview: {"secret": "TENANT_A_PRIVATE"}
after `alter view ... set (security_invoker = true)`:  NOTHING
```

A materialized view is worse: it stores its own copy of the rows and can never
respect RLS at all, so it must not be granted to a client role under any conditions.

Every class test was scoped to `relkind in ('r','p')` — ordinary and partitioned
tables — so both were invisible. There is now a test requiring that any view a
client role can read sets `security_invoker = true`, and that no materialized view
is readable by `anon` or `authenticated`. Verified three ways: the hostile view
fails, the same view with `security_invoker = true` passes, the materialized view
fails.

**RLS protects tables. A view is a different object with different rules, and it is
exactly the thing an engineer reaches for when a query gets repetitive.**

### G68 — Naming the schemas to scan is the same mistake as naming the tables
Round 5 fixed the class tests to assert by exclusion rather than by listing tables —
and then scoped them to `nspname in ('public','app')`, which is a list. A
business-scoped table in a `reporting` schema was fully cross-tenant readable and
writable while every class test stayed green:

```
tenant B reads third-schema table: TENANT_A_METRIC
schemas my class tests scan: public, app | this table is in: reporting
```

All four class tests now scan every schema **except** Postgres's own catalogs and
the ones Supabase owns, so a schema nobody has thought of yet is covered by default.
Verified: the same table now fails both the RLS and the audit-coverage test.

**"Assert by exclusion" has to be applied at every level of the hierarchy. Fixing it
for tables and re-introducing it for schemas one line up is not a fix.**

---

## Gotchas found by the sixth adversarial review

Round 6 confirmed the previous round's three deciding fixes are real — the ack
handshake catches a squatter and reports the child's stderr, dynamic segments are
scanned, the allowlist is gone — and then found **two CRITICALs in the commit whose
message was "Close the view and third-schema gaps"**. Both were reproduced here
before being fixed.

### G69 — The view check tested SELECT, so a cross-tenant WRITE through a view sailed past
The view class test added by self-review only asked `has_table_privilege(..., 'SELECT')`
and only demanded `security_invoker = true` *inside* `if (view.auth_select)`. A view
granted INSERT but not SELECT fell through the loop with **zero assertions**.

```
direct insert into posts:            ERROR: new row violates row-level security policy
same insert through the view:        INSERT 0 1
ALPHA posts: ALPHA-PRIVATE | PLANTED BY OUTSIDER
```

The check now covers SELECT, INSERT, UPDATE and DELETE.

### G70 — `has_table_privilege` returns false for a column-level grant
Widening the check to all four privileges was still not enough, and this is the part
worth remembering. The hostile grant was `grant insert (business_id, body, …)` — a
**column-level** grant — and `has_table_privilege(role, oid, 'INSERT')` reports
`false` for those. The first fix attempt looked right and the attack still passed.

`has_any_column_privilege` is the correct predicate for SELECT/INSERT/UPDATE;
DELETE has no column-level form. Only after that did the replay fail as it should.

**Two functions with almost the same name answer different questions, and the one
that reads more naturally is the wrong one.**

### G71 — The function check tested three roles inside `app` and only `anon` outside it
`public` is precisely what PostgREST exposes as `/rest/v1/rpc/<name>`, and
`authenticated` — not `anon` — is the tenancy threat model. A `SECURITY DEFINER`
function in `public` granted to `authenticated` returned every tenant's posts with
the suite green:

```
BETA reads via public.all_posts(): 1 posts across ALL tenants   (BETA is a member of BUSINESS_2 only)
class test checks only anon outside app: anon_exec=false -> PASSES
```

The three-role assertion now applies in every schema we own, against an allowlist of
the five helpers a browser session may legitimately call.

### G72 — Exempting a schema also exempts anything of ours that lands in it
The previous round excluded `extensions` wholesale from the class tests — while
`0010` grants `authenticated` USAGE on that schema. A business-scoped table created
there was cross-tenant readable with every test green.

Extensions bring hundreds of functions nobody here wrote, so the exemption is real —
but it is now expressed as *"this function belongs to an extension"*
(`pg_depend.deptype = 'e'`), not *"this function is in that schema"*. Tables in
`extensions` are checked like any other.

### G73 — Next compiles `.js` and `.jsx`; every guard collector filtered on `.ts`/`.tsx`
Next's default `pageExtensions` is `['tsx','ts','jsx','js']`. An `app/leak/page.jsx`
with no session guard, an inline unguarded `'use server'` action, and a live query
against `businesses` — plus an `app/api/leak/route.js` returning every business —
both built into real routes and were **invisible to every check in the guard file**.
Test count identical to the clean repo.

All collectors now match `/\.(m|c)?[jt]sx?$/`.

### G74 — A route handler can live at a path the proxy matcher exempts
The matcher excludes media extensions so files in `public/` are served rather than
redirected. But a route handler can sit at *any* path, including one ending `.png`:

```
/dashboard   -> 307 /login
/api/leak    -> 307 /login
/export.png  -> 200 {"businesses":[],"marker":"NO-PROXY-NO-GUARD"}   security headers: NONE
```

Static assets and routes cannot be told apart by path, so the rule is now asserted
from the other side: no `app/**/route.*` may sit at a path the matcher excludes.

### G75 — The scanner read one URL shape per route, with one verb
A route returning the service-role key only for `?format=full` passed cleanly, as
would anything behind a POST. The scan now issues a query-string variant for every
route and a POST for every route handler.

### G76 — `redirect: 'follow'` throws away the redirect's own headers
The scanner's comment said *"Header values count too: a secret in a Set-Cookie or a
custom header ships"* — and then followed redirects, discarding exactly those
headers. A route appending the service-role key to `Set-Cookie` on a 307 passed the
whole scan. Worse, a route that redirected was `continue`d past entirely, so **six
of sixteen documents were silently unscanned** while the run reported success.

Redirects are now `manual`: every response is inspected, headers included, and a
redirect whose destination is not itself scanned is a failure rather than a note.
Coverage went from 10 responses to 24.

### G77 — A production build with no `APP_ORIGIN` bakes `allowedOrigins: []`
Which makes Next fall back to deriving the expected origin from forwarded headers —
the exact behaviour the config comment claims it prevents. `npm run verify` was
itself building this way. The build now fails outright rather than shipping a config
that quietly does the opposite of what it says.

### G78 — `npm run db:down` destroys the append-only audit log
`0009`'s rollback goes to real trouble not to delete a business that is in use, and
then `0004`'s drops `audit_log` two steps later — the one table whose entire design
premise is that no role can delete a row from it. Append-only triggers cannot stop
`DROP TABLE`, so the guard lives in the runner: `down` refuses while `audit_log` has
rows unless `ALLOW_DESTRUCTIVE_ROLLBACK=yes` is set explicitly.

### G79 — The lesson, stated once: a filter is a claim about a population
Round 6's summary is the most useful sentence produced in six rounds: *"Every class
test models the codebase with a regex or a relkind filter, and the filter is always
narrower than the thing it claims to cover."* Six rounds, six variants — `.tsx` not
`.jsx`, `('public','app')` not every schema, `relkind r/p` not `v/m/f`, SELECT not
every privilege, `anon` not `authenticated`, table-level not column-level.

Each class test now carries a **completeness assertion**: the set it enumerated must
equal the real population — every routable file on disk is picked up by a collector,
every relation kind present in a schema we own is covered by some check, `public`
and `app` are actually being scanned. The narrowing itself now fails, rather than
the seventh variant being found by a reviewer walking a row across a tenant boundary.

Round 7 then found four more variants anyway (G80–G86). The correction that mattered
was not another widened filter: it was noticing that two of the completeness
assertions were themselves unfalsifiable. *"`public` and `app` are actually being
scanned"* can only detect a schema of ours going missing from the scanned set — it
can never detect one of our objects landing in an excluded one. An assertion that
cannot fail is not evidence. Both were replaced with **diffs against a baseline**
(G82) rather than claims about a list.

### G80 — Nothing in the project knew the `pages/` router existed
Every collector in `tests/app/guards.test.ts`, every route convention the proxy
models, and `routeTable()` in the secret scanner all describe the **App** router.
A `pages/api/export.png.ts` file is a real, built, registered endpoint that none of
them saw. Serving the service-role key, it answered an anonymous `GET` with **200,
no security headers, no guard** — and the secret scan still reported the same
"8 routes" as a clean tree, because it read only `app-paths-manifest.json`.

This is G74 (a route parked on a media extension the proxy matcher excludes)
reproduced verbatim, one router over — which is the point: the fix had been written
against the *instance*, not the class. Now the scanner reads **both** manifests, and
a test bans the `pages/` router outright with the reason attached, because this
project is App Router only and deleting the ban is not the same as writing the
guards.

### G81 — `EXECUTE` is not the only way a function runs, and a `RULE` is not a relkind
Two live cross-tenant paths, both invisible to every database class test, both at an
identical 275/275:

- **A rewrite `RULE`.** `CREATE RULE ... DO INSTEAD INSERT INTO public.posts` runs
  with the *rule relation owner's* privileges — the migration superuser — so RLS on
  the target is never applied. Verified directly: a member of BETA had a direct
  insert into an ALPHA post rejected (`new row violates row-level security policy`)
  and the identical insert through a staging table carrying such a rule returned
  `INSERT 0 1` and landed in ALPHA. A rule is not a `relkind`, so it escaped the
  table checks, the view checks and the relkind completeness assertion alike —
  nothing in the suite read `pg_rewrite` at all.
- **A `SECURITY DEFINER` trigger function.** Postgres checks `EXECUTE` at
  `CREATE TRIGGER` time, not at fire time. A definer function with execute revoked
  from `public`, `anon` **and** `authenticated` — so the "only the intended roles
  can execute anything" check reported `false` for all three and passed — still ran
  on every insert the caller made, copying every tenant's posts somewhere readable.
  The premise of that check, *a definer helper is safe if nobody can call it*, is
  simply false for trigger functions.

Rules other than the automatic `_RETURN` that backs every view are now banned, and
trigger functions are held to a reviewed list — a named list is right here, because
the safety of a definer trigger cannot be derived from privileges at all.

### G82 — An exclusion list is still a list; diff against a baseline instead
G68's lesson was *"naming the schemas to scan is the same mistake as naming the
tables"*, and the fix inverted it into `OUR_SCHEMAS` — which excludes `auth`,
`storage`, `realtime`, `vault` and six more **by name**. On a real Supabase project
`authenticated` already holds `USAGE` on `storage`, so a business-scoped table and a
non-`security_invoker` view over `public.posts` created there were reachable and
invisible to all four class tests.

Worse, the test harness could not even represent the attack: `tests/db/supabase-shim.sql`
created only `auth`, `vault` and `extensions`, so the exclusion list named schemas
that **did not exist in a single test**. The exclusion had never been exercised.

Two fixes. The shim now models the schemas a real project ships with. And the
scanned set is no longer a claim: every object our migrations create is diffed
against a database carrying the shim and nothing else, and anything landing outside
`public`, `app` or `extensions` fails.

### G83 — The RSC flight probe read zero flight payloads
`scripts/check-no-secrets.ts` was rewritten in round 5 specifically to reach the RSC
flight payload — *"exactly where the old scan could not look"*. It sent the `RSC: 1`
header. Next requires the `_rsc` **query parameter** too and 307s without it, so all
eight probes were redirects, every one silently absorbed into the *"redirects to a
route scanned on its own turn"* note. The channel the whole live-server rewrite
existed to read was read **zero times**, for two rounds, while the check reported
success.

And `_rsc` takes **no value**: measured against this build, `RSC: 1` alone gives 307,
`?_rsc=1` gives 307, `?_rsc` gives 200 and the payload.

The headline number hid it. "24 responses scanned" was true while 14 were redirect
envelopes, none was a flight payload, and three of eight routes never rendered at
all — scan mode reports a *verified* session, and `/mfa/enroll` and `/mfa/verify`
both redirect a verified user away, so they could not render by construction. Scan
mode now carries a **state**, so the app can be read as each session state it
supports, and the scan asserts every route rendered a document in at least one of
them. Volume is not coverage: the scan now prints `9/10 routes rendered, 15 flight
payloads`.

### G84 — The canary list did not cover the secrets the project declares
Three names were canaried, one of which (`SUPABASE_DB_PASSWORD`) this project does
not use. `DATABASE_URL` and `ADMIN_PASSWORD` — both in `.env.example`, both genuinely
secret — were not. A page printing both shipped the database superuser password and
the admin password to the browser, and the check named *"no secret appears in the
client bundle"* passed. The canary set is now checked against `.env.example`: every
server-only name is canaried or declared non-secret **with a reason**.

### G85 — Two guards were never widened when their siblings were
G62 widened the action collector to the project root and G73 widened the file regex
to `/\.(m|c)?[jt]sx?$/`, and in both cases some checks in the same file were left
behind. `actionFiles` still read `/\.tsx?$/`: the identical file was checked as
`danger.ts` (5 failures) and completely unchecked as `danger.js` — registered in the
server-reference manifest, callable, and invisible to `tsc` too because
`allowJs: false`. The two service-role reachability checks still walked `lib` and
`app` only. G63's anonymous-default ban still matched only
`export default function (`, so `export default async () => {}` — a service-role
delete of every business, no CSRF, no session check — left `DECLARATION_FORMS` and
`everyExportedBinding` **both empty**, satisfying the equality guard with two empty
lists, which is the exact coincidence G63 was written to prevent.

### G86 — Nothing connected quality bar 4 to server actions
Bar 4 says *every mutating action writes an `audit_log` row*. It was proved entirely
by the six database row triggers — `grep -rn recordAudit tests/app/` returned
nothing. An action whose effect is not a row write leaves no trigger to fire, and
`switchBusinessAction` is exactly that shape: it sets a cookie. Every action already
audited, so the rule needed no exception list; it just was not being enforced.

Two smaller ones from the same round, fixed without incident: `vitest.config.mts`
collected only `tests/**/*.test.ts`, so a `.test.tsx` file would have sat in the repo
never running and counted as coverage to anyone reading the directory; and
`0010_lock_down_functions.sql` carried a standing
`alter default privileges in schema extensions grant execute on functions to
authenticated`, which — combined with the function class test exempting
extension-owned functions — would have made any future `create extension` in that
schema **auto-granted and auto-exempt** at the same time. Replaced with an explicit
grant over what exists now.

---

### G87 — A trigger's blind spot was the TABLE's schema, not the function's

`0010` revokes `EXECUTE` on everything in `app` and G81 added a reviewed-list of
trigger functions, because a `SECURITY DEFINER` trigger runs regardless of who may
call it. The enforcing query joined `pg_trigger` to the table and filtered on the
TABLE's namespace through `OUR_SCHEMAS` — which excludes `auth`, `storage`,
`realtime` and the rest, schemas every real Supabase project has.

So a definer function in `app` (a schema that IS scanned, and where the function
passes every other check precisely because nobody holds `EXECUTE` on it), attached
to a trigger on `auth.users`, could never appear in the enumerated set. `.toEqual()`
cannot fail on a row the query structurally excludes. One `insert into auth.users`
— a second sign-up — copied every tenant's posts into the attacker's business.

Verified directly: the query returned exactly its three known functions while
`auth.users -> app.mirror_posts` sat alongside them in `pg_trigger`.

The population is now every non-internal trigger that **either runs one of our
functions or sits on one of our tables**, whichever schema each is in, listed as
`table -> function` because both halves matter. Supabase's own triggers run
Supabase's functions on Supabase's tables, so they match neither half and stay out.

### G88 — Diffing the set of objects cannot see a `GRANT`

G82 replaced the schema exclusion list with a baseline diff: snapshot every object
before the migrations, snapshot after, and fail if anything new landed outside the
scanned schemas. That is falsifiable only for objects being **created**.

`grant usage on schema auth to authenticated; grant select on auth.users to
authenticated;` creates nothing. `auth.users` is already in the baseline, so it is
filtered out of the diff, and `auth` is excluded from every other class test. Two
lines in a migration hand every user's email address to every signed-in member of
every tenant. Verified: **109/109 green** with that grant applied.

The same hole covered `ALTER ... OWNER TO`, column-level grants (which live in
`pg_attribute.attacl`, not `relacl`), and attaching a trigger to a baseline table.

The snapshot is now a signature, not a name: each object carries its ACL and its
owner, schemas carry `nspacl`, columns with an `attacl` are listed individually, and
triggers are listed as objects. A `GRANT` changes the signature, so the diff sees it.

### G89 — "This page is dataless" was a claim about one file, not about what the page runs

Two separate checks — `RENDERS_NO_DATA` in the guards test and `datalessRoutes()` in
the secret scanner — excuse a page from the session requirement by greping **that
page's source** for `.from(` / `.rpc(` / `createSupabase`. Neither followed imports.

Move the query one module away and both certify the page as dataless:

```ts
// app/login/page.tsx — an anonymous route
import { everyTenant } from '@/lib/reporting'   // service-role client, no RLS
const tenants = await everyTenant()
```

Anonymous `GET /login`, no cookies, rendered every business in the system.
Verified: **166/166 green**, build clean, secret scan clean — the scan's canary grep
does not fire because the leak is tenant data, not the server's own env secret.

Both checks now read the file **plus its transitive local imports**
(`scripts/module-closure.ts`). Two details that matter:

- A module whose FIRST statement is `'use server'` is skipped. It is a separate
  entry point reached only by a POST, with its own CSRF/session/audit checks; without
  this, every page that renders a form looks like it queries at render time. An
  INLINE `'use server'` inside a function body is not first, so that file stays in.
- The patterns differ by scope. In the page file itself, merely constructing a client
  is suspicious. Across the closure it is not — `csrfField()` builds one to bind the
  token to the session subject — so the closure is checked for an actual **query**.

### G90 — An action's return value is a channel the secret scan cannot read

Server actions are POSTed to the page they live on; the scanner POSTs only route
handlers, and its flight probe is a GET. Reaching an action needs a live session and
a CSRF token. So an action returning `` `db=${process.env.DATABASE_URL}` `` passes
the guards test (it is CSRF-checked, session-guarded and audited — everything that
test asserts) and passes the full secret scan.

Rather than claim coverage the scan does not have, the channel is closed: every
action in this phase reports its outcome by redirecting, and a test requires each one
to declare `Promise<void>`. Confirmed falsifiable — changing one action to
`Promise<string>` fails it.

### G91 — The ninth variant: `require()` is an import too

G89 made the "this page is dataless" claim read the transitive import closure.
Round 9's brief predicted a ninth variant of the same defect and named the place to
look. It was there:

```ts
const specifiers = [...source.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)]
```

`require` is missing. `const { everyTenant } = require('@/lib/reporting')` on an
anonymous page read every tenant in the system through the service-role client with
the guard suite at **96/96**. A module reached by `require` runs exactly like one
reached by `import`; only the regex disagreed.

Two more holes surfaced while fixing it, both worse than the first because they fail
*silently* rather than by omission:

- **A computed specifier.** My first fix rejected an argument whose first character
  was not a quote. `import('@/lib/repo' + 'rting')` starts with a quote, so it read
  as literal, the specifier regex extracted `@/lib/repo`, that resolved to nothing,
  and the page was certified dataless again — **96/96**. The whole argument has to be
  a single quoted string, not merely start like one.
- **A specifier of ours that resolves to nothing.** A package import legitimately
  resolves to nothing. One starting `@/` or `.` that does not is a module we failed
  to follow, and silently treating it as absent is how the above stayed green.

Both now mark the closure incomplete, and `closureSource` **throws** rather than
return a partial graph: a caller asking "does anything here query the database" must
never get a confident no built from modules that were never read.

The general form, which is the same one G79 stated and the loop keeps re-deriving:
an incomplete model must fail, not return its incomplete answer.

### G92 — `freshDatabase()` does not isolate roles, because roles are cluster-wide

While attacking the round-8 fixes I ran a probe migration containing
`grant service_role to authenticated`. The suite correctly went red. But roles in
PostgreSQL are **cluster** objects, not database objects, so dropping and recreating
the scratch database did not undo the grant: every later run inherited it, and
`npm run verify` came back **15 failed / 265 passed** on a tree whose only change was
a comment. It took a moment to realise the failures were mine and not the code's.

Two things follow. For anyone probing this suite: a migration that touches a ROLE,
a TABLESPACE, or anything else outside the database leaves state behind that
`freshDatabase()` cannot clean, so undo it by hand. And more usefully — this is the
one privilege change the class tests genuinely cannot see, because the object it
alters is not in the database being snapshotted. It is caught today only
behaviourally, by the audit tests noticing that `authenticated` suddenly holds
privileges it should not. That is a real check, but an indirect one, and it is
recorded here rather than dressed up as coverage.

### G93 — The tenth variant, and the accounting that should have been there all along

Round 10 found three more misses in `scripts/module-closure.ts` — the file written
to close round 9's finding, which was itself in the file written to close round 8's.
Two rounds running, the defect was in the fix for the previous defect.

- **A comment between `import(` and its specifier.** The extractor read RAW source
  and needed the quote to follow the paren; `hasUnanalyzableSpecifier` read
  COMMENT-STRIPPED source and saw one clean string. So
  `import(/* webpackChunkName: "reporting" */ '@/lib/reporting')` was neither
  followed nor flagged — **96/96 green**, anonymous `/login` serving every tenant.
  `/* webpackChunkName */` is an ordinary idiom, not an exotic shape.
- **A `baseUrl` import.** `tsconfig.json` sets `"baseUrl": "."`, so
  `import { everyTenant } from 'lib/reporting'` is OURS. `resolveSpecifier` knew only
  `@/` and `.`, returned null, and the caller read null as "a node_modules package".
  Round 9's fail-closed rule only covered `@/`- and `.`-prefixed specifiers, so it
  did not apply. **Full `npm run verify` green — 281 tests, 9/9 secret checks.**
- **`/\.from\(|\.rpc\(/` is a model of supabase-js, not of reading data.** A raw
  `fetch()` to PostgREST with the service-role key matches neither, and neither did
  the page's own-source ban. Same leak, **281/281 green**.

The first two fail SILENTLY, which is worse than the omission G91 fixed.

**The fix is not a wider regex.** The critic's diagnosis was exact: `closureOf`
returned a file list with no accounting of how many import sites it had seen. So it
now counts them — every syntactic site that can pull in a module, against every
specifier actually extracted — and reports an incomplete graph when the two disagree,
*whatever the reason, including one nobody has thought of yet*. Extraction and the
unanalyzable check now read the same comment-stripped source. `isPackage()` asks
whether the package exists in `node_modules` (or is a Node builtin) instead of
inferring it from a prefix.

And the dataless claim stopped using a pattern at all. There is no finite list of
ways to read data — `pg`, `supabase.auth.admin`, a route handler imported and called
— so `DATALESS_PAGE_CLOSURES` enumerates the exact set of modules each such page
runs, and anything new in that set fails until a person reads it. That is sound only
because the graph is now provably complete; as a pair, the enumeration and the
accounting are what the previous three fixes were missing.

### G94 — A `Promise<void>` annotation is a claim about the declaration, not the value

G90 closed the flight-payload channel by requiring every action to declare
`Promise<void>`. `as any` is assignable to `void`, so this typechecks, the annotation
still reads `Promise<void>`, and the object ships:

```ts
return { leaked_database_url: process.env.DATABASE_URL,
         leaked_service_role_key: process.env.SUPABASE_SERVICE_ROLE_KEY } as any
```

Round 10 proved it on the wire with a real server-action POST, correct React reply
encoding, and both secrets in the response body — with `npm run verify` at **exit 0**.
Quality bar 2 was false while every check reported success.

The body is now checked as well as the signature: an action may `return` to exit
early, but never a value. The general lesson is the same one G93 states — a type
annotation is a claim, and a test that reads the claim is not testing the thing.

### G95 — `tgenabled` is not `exists`

The audit-coverage class test asked whether a trigger row existed. `ALTER TABLE
public.businesses DISABLE TRIGGER audit_changes` leaves the row in `pg_trigger` with
`tgenabled = 'D'`, so the answer stayed yes while insert, update and delete produced
**zero** audit rows — 280/280 green, bar 4 false for that table. The same ALTER on
`posts` was caught, but only because `audit.test.ts` happens to exercise posts
behaviourally; real coverage was exactly the set of tables someone had written a
behavioural test for.

The check now requires `tgenabled in ('O','A','R')`, and the baseline signature
carries it too, so disabling a trigger changes the snapshot. (`tgenabled` is
PostgreSQL's `"char"` type — it needs an explicit `::text` cast to concatenate, and
without it the query fails with `operator is not unique: text || "char"`.)

## Known, accepted limitations

Stated plainly rather than left to be discovered.

1. **The MFA round trip has never run against a live Supabase project.** No project
   or credentials were available in this environment. The enrol/challenge/verify
   call shapes were written against the current documented API and the failure paths
   are tested, but the successful round trip is unproven. This is the single largest
   untested surface in the phase.
2. **The Vault used in tests is a pgcrypto stand-in**, not the real Supabase Vault.
   Call shapes match; the encryption does not.
3. **Audit writes are best-effort for ordinary actions, mandatory for security
   events.** `recordAuditOrThrow` fails the request if the row cannot be written, and
   is used for sign-in, sign-out, MFA enrol/verify and business switching.
   `recordAudit` logs and continues, and is used where losing a row costs visibility
   rather than accountability. Row changes are recorded by database triggers, so they
   cannot be lost this way at all.
4. **Failed-login audit rows record the attempted email address.** Deliberate — you
   cannot spot credential stuffing without it — but it is personal data in a table
   that by design can never be deleted.
5. **A user removed from a business keeps read access to their own historical audit
   rows** in that business, via the `actor_user_id = auth.uid()` branch of
   `audit_select_own`.
6. **`APP_ORIGIN` must be set in production.** CSRF and Next's Server Action origin
   check both compare against it. If it is unset, every mutation fails closed —
   deliberately, since the alternative is trusting a client-supplied header.
7. **`app.write_audit` accepts a caller-supplied action string.** A trusted
   server-side caller could record an action that did not happen. Only `service_role`
   can reach it, so this is a compromised-server scenario, not a tenant one — but
   note `metadata.actor_source` will read `caller`, not `jwt`, for every such row.
8. **Scan mode is a bypass, and bypasses are risk.** `lib/security/scan-mode.ts`
   lets the local secret scanner render authenticated pages. It is inert unless
   `SECRET_SCAN_TOKEN` is set, requires a matching header compared in constant time,
   refuses to run unless `APP_ORIGIN` is a local address, and is deliberately absent
   from `.env.example`. The scanner asserts all four fences. It is still a bypass,
   and it is the single thing in this codebase most worth re-reading before deploy.
9. **The secret scan renders against a stand-in for Supabase**, not the real thing.
   Every route is inspected and there is no exclusion list, but the rows are empty
   and the auth endpoint returns 401. It answers "do the server's own secrets reach
   the browser", not "is the data correct".
10. **There is no rate limiting anywhere.** `signInAction` in particular can be
   called repeatedly by an unauthenticated caller, and each failure appends a row to
   a table that by design can never be pruned. The email is capped at 320 characters
   so the growth is bounded per attempt, but not in total.
11. **There is no retention or erasure path for audit_log.** Append-only is enforced
   against every role, which is the point — and it means a GDPR erasure request
   touching the failed-login rows cannot currently be honoured.
12. **`TRUSTED_PROXY_COUNT` must match the deployment.** The audit IP is read that
   many entries from the end of `X-Forwarded-For`. Set it wrong and the recorded
   address is wrong — silently.
