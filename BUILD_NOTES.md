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

### G96 — The proof was computed and then thrown away

Round 10's diagnosis was that `closureOf` returned a file list with no accounting of
how many import sites it had seen. G93 added exactly that accounting. Round 11 found
that `closureOf` has **two** consumers and only one was wired to it:

```ts
export function moduleClosure(entry, root) {
  return closureOf(entry, root).files      // .unanalyzable dropped on the floor
}
```

`closureSource` threw correctly. But the dataless-page guard calls **`moduleClosure`**,
so the completeness proof was computed and discarded before it reached the one check
that certifies a page reads no tenant data. A computed dynamic import walked straight
through: **96/96 guards, 281 tests, 9/9 secret checks, exit 0**, with an anonymous
`GET /login` serving every tenant. The page file contained no `fetch(`, no `.from(`,
no `createSupabase` — the page-source ban was satisfied honestly. The break was
entirely in the accounting not reaching the guard.

Worse, the comment in that test said the check "is sound only because closureOf now
proves the graph is complete … rather than returning a short list when it fails to
follow something" — and `moduleClosure` returned precisely that short list when it
failed to follow something. The comment was true of `closureOf` and false of the
function the test actually called.

There is now one `assertComplete()` gate, and no way to read the files without
passing it. The lesson is narrower and more useful than "widen the regex": **a check
is only as good as its narrowest consumer.** Adding a proof is half the work;
verifying every caller is forced through it is the other half, and it is the half
that was missing in three consecutive rounds of fixes to this one file.

Also closed, both found by round 11 probing the site-counting regex directly:
`new Worker(new URL('./x', import.meta.url))` and
`createRequire(import.meta.url)('./x')` load a module with no `import(`/`require(`
token, so they produce neither a site nor a specifier — the counts agree and the
module vanishes. Neither is a normal server-component data path, so their presence
alone now marks the graph incomplete rather than being resolved.

And in `scripts/check-no-secrets.ts`, `datalessRoutes()` filtered on RAW source, so
the word "supabase" in a **code comment** was enough to skip the closure check
entirely. It reads comment-stripped source now, like everything else here.

### G97 — Stop grepping for imports. Ask the compiler.

Four rounds widened a regex that stood in for the question *"what modules does this
file pull in"*, and each round found the next gap: `require` (G91), a webpack magic
comment and a tsconfig `baseUrl` specifier (G93), then a **false positive** —
`Buffer.from('postdeck.csrf.v1', 'utf8')` in an honest module made the completeness
gate throw with a message telling the engineer to "use a literal import" in a file
that has none. A check that cries wolf is one somebody eventually weakens.

TypeScript is already a dependency and already answers this question exactly.
`ts.preProcessFile()` understands `import`, `export … from`, `import x = require()`,
`require()` and dynamic `import()`, and returns **nothing** for `Buffer.from`,
`c.from('t')`, or the string `import 'x'` inside a JSX attribute. The extraction
regex, the site-counting regex and the comment-stripping that fed them are all gone.

Two AST checks remain because `preProcessFile` alone is not enough:

- It returns the literal **head** of a concatenated specifier (`import('@/a' + 'b')`
  yields `'@/a'`), which would resolve to the wrong module while looking complete.
  So a walk over the tree flags any `import()`/`require()` whose argument is not a
  single string literal.
- Some modules load code without naming it in an import. The old check matched the
  spellings `new Worker(` and `createRequire(`, which `new wt.Worker(...)` and
  `createRequire as cr` both defeat. The test is now on the **import** —
  `node:worker_threads`, `node:module`, `node:vm`, `node:child_process` — which no
  alias can hide.

### G98 — "It doesn't run at render" was an assertion, not a checked property

`closureOf` deleted any module whose first statement was `'use server'`, *before* any
accounting ran — no site, no specifier, no `unanalyzable` entry. The docstring's
premise, "nothing in it runs while the importing page renders, it is reached only by
a POST", is false twice over: module-level statements execute at import, and an
exported action is an ordinary async function a server component may call inline.

Two proofs, both anonymous `GET /login` returning every tenant at **exit 0**:

- A new `lib/boot.ts` beginning `'use server'` with **zero exports** — so it satisfied
  every per-export action check vacuously — doing its work in a module-level statement.
  285/285.
- No new module at all: the leak inside `app/login/actions.ts`, which the page already
  imports and the resolver already dropped, awaited by the page. 281/281, and
  `DATALESS_PAGE_CLOSURES` unchanged because the module set never moved.

Action modules are now followed like any other, so they appear in the enumerated
closure and a new one fails the set comparison. For the second variant the set does
not move, so the rule is stated directly: **a dataless page may pass a server action
to a form, never invoke it.** Invoking it runs that module's queries at render.

### G99 — Three conventions that render on the server were checked by intent

- `app/layout.tsx` wraps every page including the anonymous `/login`, and was checked
  by grepping **its own file** for `.from(`/`.rpc(` — the same supabase-js model G93
  had already rejected for pages, and blind to a helper one import away. A layout
  reading every tenant through such a helper passed at 174/174 and served the rows.
- `loading.tsx` and `error.tsx` were skipped by filename under the comment "purely
  presentational conventions render no data of their own". That is an assertion about
  intent. `loading.tsx` is a server component whose output streams to the browser;
  one reading every tenant passed the whole suite, rows visible in the flight payload.
- The metadata routes had the identical own-file weakness, and those responses are
  exactly what a CDN caches.

All of them now ask the question of the **closure** rather than the file, and the
fallbacks are collected rather than exempted.

### G100 — The flight payload was not the only way out of an action

G94 closed the return channel and the comment said the channel was closed. There were
two more, and both are the house idiom rather than exotic: every action already
reports outcomes by redirecting with a query parameter, so
`redirect(LOGIN_PATH + '?k=' + process.env.SUPABASE_SERVICE_ROLE_KEY)` satisfied the
`Promise<void>` signature, the return ban, and all 9 secret checks — while a 303
`Location` header carried the service-role key to an anonymous caller. Cookies are the
same shape. The scan cannot see either, because it never POSTs an action.

Redirect targets and cookie values may no longer be built out of `process.env`.

### G101 — Stop modelling. Watch.

Five consecutive rounds found the defect inside the previous round's fix, always in
the same place: the guard claiming a page reads no tenant data. The models tried, in
order — which module-naming syntax appears in the file; the same via the TypeScript
compiler; the set of module PATHS the page reaches — each closed the previous hole
and opened the next. Round 13 named why, exactly:

> The extractor converged; the property did not. The set of module paths is invariant
> under editing any of those 11 files.

`lib/security/csrf.ts` is module #6 of the eleven `/login` runs, and the page has
always called `await csrfField()`. A `pg` client opened inside it read every business
and served it to an anonymous browser with **285/285 and 9/9 passing**. Nothing static
could see it: the module set did not change, `pg` is an external package, and the
page file was byte-identical.

So the check stopped being a model. `scripts/render-probe.cjs` is loaded into
`next start`, and `check-no-secrets.ts` renders **every route anonymously** — no scan
header, a genuinely unauthenticated browser — with the probe log cleared before each,
and fails if that render performed a data read. There is no list to keep in step with
the code and no page can be excused by a comment or a filename, because the property
holds for every route: a guarded one redirects before it reads, an unguarded one has
nothing tenant-scoped to show.

**The seam matters, and I got it wrong first.** Version one hooked `Module._load` to
catch `require('pg')`. It works in plain Node and is useless here: Next's bundler
resolves `await import('pg')` inside a server component without going through Node's
loader. I only found that because I distrusted a passing result and instrumented the
leak itself — the injected code ran **29 times**, imported pg, constructed a Client
and reached a real Postgres, while the probe recorded nothing and the scan reported
success. That is precisely the false green this probe exists to end, produced by the
probe. The seam is now `net.Socket.prototype.connect`: every driver, bundled or not,
ends up opening a socket, and `net` is a core module the bundler cannot inline.

Auth traffic is deliberately not a data read — `/login` legitimately asks the auth
server who the caller is — so the line is PostgREST and live SQL connections, which is
exactly where the property draws it.

### G102 — Three checks that were still patterns, and a name the attacker chooses

- **The redirect ban** captured the text between `redirect(` and `)` and looked for
  `process.env`. One local `const` hoisted the read one line up and emptied the
  capture; the service-role key shipped in a 303 `Location` header to an anonymous
  caller with all 9 secret checks passing. `headers().set`, a thrown message and
  `revalidatePath` are the same hole in different spellings. No action in this phase
  needs an environment variable, so none may read one — the value is denied at its
  source rather than at each of its exits.
- **`FORBIDDEN_IN_PUBLIC`** matched secret-*sounding* names. Renaming `DATABASE_URL`
  to `NEXT_PUBLIC_DATABASE_URL` passed it *and* removed the variable from the canary
  population, which filters `NEXT_PUBLIC_` out. The count went from "8 checked" to
  "7 checked" and nothing objected. The name is the attacker's to choose, so the
  public variables are enumerated: exactly two values are meant to reach the browser.
- **The layout/fallback closure check** was five regexes; `await import('pg')` matched
  none of them (`from 'pg'` is a static-import spelling). The runtime probe covers
  this now regardless of how the read is written.

### G103 — The README told people to run commands that do not work

Three defects in a document I had written a few hours earlier, found by pointing the
reviewer at it:

- Steps 2 and 3 said to fill `.env.local` and then run `npm run db:up` and
  `npx tsx scripts/seed-admin.ts`. `tsx` does not read `.env.local` — only
  `next dev|build|start` do — so both fail on a clean checkout with
  `DATABASE_URL is not set`. The most natural workaround,
  `export $(cat .env.local | xargs)`, puts the service-role key into shell history and
  every child process. The scripts now load it themselves via Node's
  `--env-file-if-exists`, so the documented steps are true.
- It stated that `test:secrets` "fails the build if you do" prefix a server variable
  with `NEXT_PUBLIC_`. It did not, until G102.
- It said "ten migrations". There are eleven.

A README that tells someone to do the wrong thing is a defect like any other, and this
one had never been reviewed by anybody.

### G104 — `service_role` could TRUNCATE the audit log

`0006` revokes TRUNCATE from `anon` and `authenticated`, with a correct explanation of
why it matters: RLS does not filter TRUNCATE, and TRUNCATE fires no row triggers, so
the append-only triggers never see it. It missed that Supabase also grants ALL to
`service_role` — the role this app's own server runs as. The trail our own code writes
was destroyable in one statement by our own code.

The test was named *"even a signed-in user cannot TRUNCATE, so the audit log cannot be
wiped"* and only ever tried it as a signed-in user; the clause after the comma was
false. It now checks every role that exists, and asserts it checked three.

### G105 — A data read is not a socket handshake

Round 14's verdict on the runtime probe: relocated a sixth time. Its statement of
why is the clearest thing anyone has written about this loop:

> A data read is not a handshake. It is a handshake PLUS every query afterwards on
> that socket PLUS every byte baked into a cache by an earlier render.

Three bypasses, each with the whole suite green:

- **A pooled connection.** The connect happens once, at boot or during an earlier
  phase of the scan whose records the probe loop then wipes. Every render afterwards
  reuses the idle socket: no connect, no fetch, probe log **0 bytes**, two tenants'
  private post bodies delivered to a browser with no cookie.
- **A build-time read served from cache.** `app/sitemap.ts` is prerendered, and the
  probe was only in `next start`'s NODE_OPTIONS, never in `next build`. At request
  time Next serves the cached artifact, so the render the probe watches reads
  nothing. The rows were baked into `.next/server/app/sitemap.xml.body` and served to
  an authenticated user of a *different* tenant. A build-time read is strictly worse
  than a request-time one: computed once, served to everyone, forever.
- **`node:http` to `/rest/v1/`.** The fetch seam is on `globalThis.fetch`, which
  `node:http` never touches; the socket seam exempts the Supabase port, which is
  exactly where PostgREST lives. One request defeated both seams at once.

The probe now watches **traffic, not connections**: sockets are tagged at connect and
inspected at every WRITE, so a query on an already-open connection is a read; `fetch`,
`node:http` and `node:https` are all read for a data-plane path
(`/rest/v1/`, `/graphql/v1`, `/functions/v1/`) because the auth and data planes share
a host and port and only the path separates them; and the probe rides `next build` as
well as `next start`.

### G106 — The probe crashed honest code and slandered the rest

Two defects in the probe I had written hours earlier, and the round was right to
insist they be fixed before anything else was trusted.

Node normalises connect arguments, so `args[0]` can be an **array containing a
null-prototype options object**. The hook did `String(args[0])` on that:

- It **threw** `Cannot convert object to primitive value` from inside the hook,
  before `realConnect` ran — so any dependency using the default HTTP agent (most
  SDKs, tracing agents, `node-fetch`) turned every render into a 500. The scan was
  measuring a different program than production.
- On the non-throwing path it produced the port string `"[object Object],"`, which
  never equals the allowed port — so honest auth traffic was reported as a tenant
  data read. The scan was green only by accident: its probe loop sends no cookies, so
  `getClaims()` short-circuits before touching the network. The first anonymous
  render making any outbound call would have failed the scan.

A probe that both breaks and slanders correct code is worse than no probe, because it
is the one that gets deleted. Arguments are normalised properly now and nothing is
coerced with `String()`.

### G107 — Three more checks that named a population instead of enumerating one

- **`bodyOf()` is the wrong window for reachability.** G94 correctly narrowed it so an
  action could not absorb trailing helpers; that made a helper declared BELOW an
  action sit outside the scanned text while remaining perfectly callable from inside
  it. `redirect(...?d=${diagnostic()})` with `function diagnostic() { return
  process.env.SUPABASE_SERVICE_ROLE_KEY }` passed at 100/100. Reachability is a
  property of the module, so the module is what is checked now.
- **The TRUNCATE check named three roles** and asserted the count was three — which
  guards against one vanishing, not against a fourth appearing, while its comment
  claimed "every role that exists is checked now". A role a later phase might create
  emptied the append-only trail in one statement with the test passing. It enumerates
  `pg_roles` now, exempting only superusers, because nothing in the database can stop
  those.
- **The `NEXT_PUBLIC_` enumeration read `.env.example`**, not the names the code uses.
  A variable read by application code and set in the deployment environment escaped
  both this check and the canary population, while this very check printed "only the
  2 values meant to be public carry the prefix". It reads the source tree now —
  comment-stripped, because otherwise this file's own prose about the previous
  finding reads as a usage.

### G108 — Two claims that were bigger than what was measured

The README said `test:secrets` "fails if the render opens a database connection or
calls PostgREST" — false in both halves, per G105. And the probe's summary line said
`10 route(s) rendered anonymously`, counting fetches: seven of the ten are guarded, so
the proxy redirects and the page never executes. It reads *requested* now, and says
that guarded routes redirect before rendering and that the build is probed separately.
Both are small; both are the same failure this project keeps finding, which is a
report describing something other than what happened.

### G109 — One exchange is not one account

Facebook and Instagram share a Meta app, share an OAuth exchange, and share a
credential: the Page access token. So they shared a connector, and an Instagram
connect wrote the **Page id** into `provider_account_ref`.

Nothing failed. The connect succeeded, the row looked right, the token was correct,
and the account it named could not be published to — an Instagram business account
is addressed by its own id, which you can only learn by asking the Page which
Instagram account it owns (`?fields=instagram_business_account`). The defect would
have surfaced a phase later, as a publishing bug, with the wrong id already stored
on every Instagram row anyone had connected.

They are two connectors over one exchange now. The shared part is a function; the
part that differs — which id identifies the account — is not shared, because it was
never the same thing. A Page with no Instagram account attached is skipped rather
than connected under a Page identity.

The test asserts the negative as well as the positive (`not.toBe('page-1')`), and
was checked by putting the bug back: it fails on exactly that line and nothing else.


## Gotchas found while building the scheduler (Phase 3)

### G110 — The one failure that cannot be undone is publishing twice

Everything else in this app is recoverable. A post that goes out twice is not: it is
visible to other people before anybody notices, and deleting it does not un-send it.
So the claim is not an application flag.

Two workers reading `where status = 'scheduled' and scheduled_for <= now()` will both
read the same row, and both publish it. `SELECT ... FOR UPDATE SKIP LOCKED` inside a CTE
that feeds the `UPDATE` fixes that: the second worker skips what the first has locked,
and the update is the same statement as the read, so there is no window between them.

But a database lock covers only a worker that is *alive*. A worker that dies mid-publish
releases its lock the moment its connection drops, and the row becomes claimable again —
possibly after the post has already gone out. That is why the row also carries
`locked_until`: a lease outlives the connection. The lock stops two workers colliding in
the same instant; the lease stops the next run picking up something a dead worker may
already have published. Neither one alone is enough, which is why both are there.

`attempts` increments at claim time, not at completion. A worker that dies leaves no
completion behind, so counting on completion would let a row that crashes the worker
retry until the end of time.

The test that matters here does not read the SQL. It opens two connections, begins two
transactions, calls the function in both, and asserts the intersection of the two result
sets is empty.

### G111 — `ALTER TYPE ... ADD VALUE` cannot run in a transaction

The obvious modelling was a new `post_status` value — `publishing`, say — to mark a row
in flight. `scripts/migrate.ts` wraps each migration in a single transaction, which is
the right thing for a migration runner to do and is why the whole file rolls back if any
statement fails. Postgres will not add an enum value inside one.

The choice was between weakening the migration runner for every future migration and
carrying the extra state in columns. Columns won, and turned out to be the better model
anyway: `locked_until` and `locked_by` say *who* holds a row and *until when*, which a
status value cannot express, and a lease that expires needs no state transition to
become claimable again.

### G112 — `scheduled_posts` still had a table-wide UPDATE grant

Every other table in this schema had its UPDATE grant narrowed to the columns a human
has any business writing — `posts.created_by`, `social_accounts.encrypted_credential_ref`.
`scheduled_posts` was left with `grant update` on the whole row in `0006`, and it was
harmless, because at that point every column on it was one the owner was allowed to set.

Phase 3 added `published_at`, `provider_post_ref`, `status` transitions to `published`,
and `attempts`. The instant those columns existed, that old grant meant a signed-in
owner could mark a post as published that never went out, and clear the error explaining
why it hadn't. Not a tenancy hole — RLS still confines them to their own rows — but the
row stops being a record of what happened and becomes a record of what somebody typed.

Now: `grant update (scheduled_for)`. A human can move a post in time, or delete it to
call it off. Declaring it published is the worker's job, through a `SECURITY DEFINER`
function `authenticated` cannot call. Each refusal has its own test, because a single
test that "an update fails" would pass for the wrong reason.

### G113 — A second refusal in the same transaction proves nothing

Two `expectRejected` calls in one `asUser` block. The second one passed — reporting
`current transaction is aborted, commands ignored until end of transaction block`.

Postgres had refused it because the *first* statement had already failed, not because of
the grant the test was written to prove. Remove the grant entirely and the test still
goes green. It is the project's recurring failure in a new costume: a green result that
measures something other than the thing named in the test.

One refusal per test now, with a comment saying why they cannot be combined.

### G114 — `audit_log` is append-only against me, too

A test wanted a clean slate, so it opened with `delete from public.audit_log` as the
admin client — and got `audit_log is append-only: DELETE is not permitted`.

That is G104's control, working exactly as designed, on the person who wrote it. It was
briefly tempting to reach for a way around it. The test was rewritten instead: it counts
rows for one specific scheduled post and asserts the exact sequence of actions and the
`changed_columns` on each. A stronger assertion than the one it replaced, arrived at by
being refused.

Worth recording for the same reason: the publishing functions write **no audit rows of
their own**. The `audit_changes` row trigger from `0007` already covers `scheduled_posts`,
so a function that also wrote its own row would produce two records of one event that
could later disagree.

### G115 — `datetime-local` has no timezone

The browser sends `2026-09-09T14:30`. Not UTC, not local — no zone at all. Hand that to
`new Date()` and it is read in the *server's* zone, so the same form submitted against
Netlify and against a laptop schedules two different moments.

Parsed explicitly as UTC via `Date.UTC` now, with everything displayed as UTC and
labelled UTC on both the form and the calendar. A scheduler that is subtly wrong about
time is worse than one that makes you do the arithmetic yourself.

The second half of that: `Date.UTC(2026, 1, 31)` does not fail, it returns 3 March.
Silently moving somebody's post by three days is worse than refusing the form, so the
parser round-trips the parsed date back to its components and rejects anything that
moved.

### G116 — A provider error can contain the credential

`last_error` is written into a row the operator reads, by a function whose changes land
in an append-only audit table. Meta's error text is not ours, and an auth failure is
exactly the kind of error that quotes back the token it rejected.

The publisher redacts the credential out of any message before it is recorded. The guard
on that guard: a credential under 8 characters is ignored, because a stub or near-empty
value would otherwise redact every message into noise.

### G117 — Instagram publishes in two steps, and only the second one is real

`POST /{ig}/media` creates a container; `POST /{ig}/media_publish` makes it visible.
Failing at the first step must leave nothing behind and must not have called the second,
or a retry follows a post that already went out. The connector does nothing after
`media_publish` returns — no logging, no parsing that could throw — because a throw
after the post is live turns one published post into two on the next attempt.

The test stub routes publish responses **longest key first**, or `/media_publish` gets
answered by the `/media` rule and the two-step test asserts against itself.

Also: the token travels in the POST **body**, not the query string, so it does not land
in anybody's access logs.

## Gotchas found while building the dashboard and drafts (Phase 4)

### G118 — The grant that was right in Phase 1 became wrong in Phase 4

`grant update (status, body) on posts to authenticated` has been there since `0006` and
was correct: a post is the user's own content, and content gets rewritten.

Phase 4 is the first phase where a browser can actually *reach* that grant — the composer
loads a post back and saves over it. And a post is not one thing for its whole life. While
it is a draft, rewriting it is the entire point. Once it has gone out, the row is the local
record of something other people can see, and rewriting it produces a record that quietly
disagrees with reality.

Deleting is the same shape and worse: `scheduled_posts` cascades from `posts`, so deleting
a published post takes `published_at` and the provider's id with it. The post stays up on
Facebook; the only local evidence of it is gone.

No column grant can express "editable until published", because the fact that decides it
lives on a *different table*. So `0015` is a trigger. This is the third time this project
has landed on the same answer — narrow the grant where the fact is on the row, use a
trigger where it is not.

### G119 — The exemption that was not written, and why

The obvious shape for the trigger was to check `current_user` and let `service_role`
through: the worker is the thing that sets `published_at` in the first place, so exempting
it sounds like the safe default.

It is G104 again — the round that found `service_role` could TRUNCATE the audit log,
because the control had been reasoned about in terms of who is trusted rather than which
statement is legitimate. The worker has no reason to rewrite a published post either.
Written without the exemption, and with a test that asserts the admin client is refused
too. Not because the worker was going to do this, but because a control with an exception
is a control plus a way around it, and the exception is what survives into the phase where
somebody has forgotten why it was there.

### G120 — `$4` used twice, deduced twice, inconsistently

A test helper inserted a scheduled row with `values (..., $4, case when $4 = 'published'
then now() end)`. Postgres deduced `post_status` for the first use and `text` for the
second and refused the whole statement: *inconsistent types deduced for parameter $4*.

Nine tests failed on a helper, which reads exactly like nine broken features. Worth
recording because the fix is not obvious from the message: a parameter is typed once for
the whole statement, so reusing one across two contexts needs an explicit cast — or, as
here, the branch moved into TypeScript where it is easier to read anyway.

### G121 — A date heading that depends on the server's locale

`toLocaleDateString('en-GB', ...)` produced *"Wednesday, 9 September 2026"* on this
machine and the test expected it without the comma. The reflex is to fix the expectation.

That would have been fixing the wrong end. The output depends on the host's ICU build,
which is not something the operator chose and not something the test can pin down — the
same code could render differently on Netlify than it does locally, in a heading that sits
directly above times deliberately fixed to UTC. Twelve month names and seven day names,
written out. The test now asserts a value that cannot drift.

### G122 — "Overdue" is a feature, not a status

There is no `overdue` state anywhere in the schema, and there should not be: a post whose
time has passed is still exactly `scheduled`, and adding a status would mean something has
to write it, which means a job whose own failure is invisible.

It is computed in `lib/dashboard/overview.ts` from `scheduled_for <= now`. The reason it
earns a section on the dashboard is that this is what a *stopped worker* looks like from
the operator's chair: no error, no failed row, nothing in the log — just posts that never
went out. The one failure mode this design has no other way to surface.

### G123 — Two submit buttons, two actions, one form

The composer needs to both schedule and save a draft, and the two do not share validation:
scheduling demands an account, a time, and content the platform will accept; saving a draft
demands none of that. Two separate forms would mean duplicating every field and hoping they
stay in step.

`formAction` on the second button posts the same fields to a different server action, which
is plain HTML and needs no client JavaScript. The trap avoided: the draft action must not
inherit the scheduling checks, or "save this half-written thing and come back later" —
the only reason drafts exist — stops working.


## Gotchas found while building the assistant (Phase 5)

### G124 — The one thing the assistant produces is the one thing nothing scans

Every server action in this project returns `Promise<void>` and reports by redirecting,
because a return value travels in the flight payload — a channel the secret scan
structurally cannot read (G56). That rule was written about configuration values.

Phase 5 is the first feature whose *entire output is generated text*. Returning
suggestions from the action would have put the only thing this feature makes into
the only channel nothing checks, and it would have looked completely reasonable —
it is what every tutorial does.

So suggestions go into a table and the composer reads them back. The rule paid for
itself in a case it was not written for, which is the argument for rules stated as
properties rather than as instances.

The second-order benefit was not the reason but is worth having: a suggestion cost
money, came from the operator's own draft, and is now something the audit trail can
point at.

### G125 — `post_suggestions` has no UPDATE grant, and that is the feature

The reflex is `grant select, insert, update, delete` and move on. Here update is the
one that must not exist: the table's only job is to record what the model said, and a
row that can be edited in place cannot answer "did the model write this, or did I?".

That question matters more than it sounds. The suggestion is *advice about what to
publish*, and the moment it is indistinguishable from the operator's own text, the
audit trail stops being able to attribute anything. Rewriting happens where rewriting
belongs — in the composer, on the post.

Same shape as G112 and G118: work out what the row is *for*, then grant only the
columns and commands that serve it.

### G126 — A refusal arrives as a success

`stop_reason: "refusal"` comes back as an HTTP 200 with an empty or partial
`content` array. Code that goes straight to `response.content[0].text` does not
throw — it stores nothing, redirects cheerfully, and shows the operator a composer
with no suggestions and no explanation.

Checked explicitly before the content is read, and there is a test that returns a
refusal and asserts it becomes an error. The same class as the Instagram defect from
Phase 2: the failure that looks exactly like success is the one worth a test.

### G127 — The image URL was going to be sent for no reason

The first draft of the prompt included the image address, because the composer has
it and it felt like context. The model cannot fetch it, so it buys nothing — and it
is somebody's CDN path, occasionally a signed one, sent to a third party for no
gain.

What the model actually needs is *that there is an image*, because that changes what
a good caption looks like. So the prompt says exactly that, and the test asserts the
hostname does not appear anywhere in the outgoing request.

### G128 — The provider error is a place the API key can surface

Third time this project has met the same shape: `last_error` on a scheduled post
(G116), and now an assistant failure shown in the composer. An auth failure is
exactly the error most likely to quote back the credential it rejected.

`describeAssistantError` maps the typed SDK errors to messages this app writes
itself, and the auth case names the *variable* rather than repeating the provider's
text. The test throws an error whose message contains the key and asserts the key
does not survive.

### G129 — Two enumerations that a new table had to be added to

Adding `post_suggestions` broke exactly two tests: the migration ledger's table list
and the RESTRICTIVE-MFA-policy list. Both failed with a clean diff naming the new
table.

Worth recording as the counter-example to this project's recurring failure. Those
lists are hardcoded enumerations — the thing G107 and the round-15 findings kept
catching. The difference is that these two are *closed sets asserted by equality*,
so a new member fails the test; the ones that kept failing were *filters asserted by
sampling*, so a new member silently fell outside the filter. Enumerate and compare
whole, or watch behaviour. Never filter and hope.

### G130 — Effort is a cost decision, and low is the right one here

The house default for this model family is high effort with adaptive thinking. This
call rewrites one or two sentences in somebody's own voice, three times.

`effort: "low"`, stated in a comment with its reason, because effort is the lever
that costs money and the alternative is paying for reasoning on a task that has
none. `max_tokens` is 4,000 for the same reason: three posts at Instagram's 2,200
character limit is the largest legitimate answer, and a ceiling above that only ever
pays for something going wrong.


## Gotcha from making `verify` start its own database

### G131 — "The tests are broken" was "a service is not running"

Every fresh container in this project came up with the Postgres cluster stopped, and
`npm run verify` answered with six test files failing on `ECONNREFUSED`. That reads
like the app is broken. It took a `pg_ctlcluster` command each time, remembered by
hand, and any new machine would have hit the same wall.

`npm run db:ensure` runs first in `verify` and `test:db` now. Three things it does
that are worth writing down, because each was a way to get it wrong:

**It tells "nothing is listening" from "something answered and said no."** A refused
socket is a service to start; `28P01 password authentication failed` is a server that
is already up. Treating them the same means the script tries to start a running
server, fails, and reports "could not start Postgres" — replacing the precise message
(your password is wrong) with a vague one. They arrive through completely different
channels — an OS socket error versus a Postgres error code — so the classifier reads
the code rather than the text where it can.

**It enumerates rather than guesses.** The cluster version comes out of
`pg_lsclusters`, the Homebrew service name out of `brew services list`. Hardcoding
`pg_ctlcluster 16 main start` is exactly the fix that works until somebody upgrades to
17 — the same shape as every class-test failure in this repo, in a shell command.

**It never creates a database.** `docker start` on an existing container, never
`docker run`. Creating one would invent a database whose password, port and volume
this script chose on the operator's behalf, and the first sign of that would be a
mystery second Postgres months later.

The parsers and the classifier are unit tested; the starting is proved by having
actually stopped the cluster and run `verify` cold. What is NOT proved is the macOS
and Docker paths — this container has neither `brew` nor a Docker daemon, so those two
strategies have been read and not run.


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
8. **The scanner no longer renders authenticated pages.** `lib/security/scan-mode.ts`
   was an auth bypass that let it do so, fenced four ways and still a bypass. It was
   deleted: 120 lines of production auth surface so a scanner could read three static
   headings was the worst trade in the repo for a one-person tool. The cost is real —
   the canary grep now sees a guarded route's redirect rather than its rendered HTML.
   What covers that gap instead is the render probe, which fails if a route touches
   the data plane at all, and the build probe, which fails if the production build
   does.
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
13. **Publishing has never run against the live Graph API.** The call shapes, the
   two-step Instagram flow and the failure paths are tested against a stub. The
   round trip to Meta is unproven, and is the largest untested surface in Phase 3.
14. **Images are given as a public https URL; there is no upload.** Meta fetches the
   address itself, so anything not reachable from the internet fails at publish time.
   The composer refuses `http`, `localhost`, loopback and `.local` up front, but it
   cannot tell whether a public-looking address actually resolves.
15. **Everything is UTC. There is no per-user timezone.** Deliberate for one operator,
   and wrong the moment somebody else schedules a post.
16. **A post that fails five times stops on its own and stays failed.** There is no
   automatic retry past that and no notification — the calendar shows the status and
   the provider's last error, and the operator has to look.
17. **The worker is a single pass, run by an external scheduler.** `npm run publish:due`
   claims what is due, publishes it, and exits. Nothing runs it on a timer inside this
   repo; that is Railway's job. If nothing invokes it, nothing is ever published.
18. **The lease is five minutes.** A publish that hangs longer than that can be claimed
   again by the next run while the first is still in flight. Longer leases delay
   recovery from a dead worker; shorter ones risk exactly this. Five minutes is a
   judgement about Meta's response times, not a proof.
19. **Nothing here is a calendar grid.** The calendar groups by UTC day in a list, which
   is honest about what it is. A month view with drag-to-reschedule is a real feature
   and is not built.
20. **There is no approval flow**, though `post_status` has had `pending_approval` since
   `0001`. A single operator approving their own posts is theatre; the enum value is
   left for a phase that has more than one person in it.
21. **A published post cannot be edited or deleted through this app at all** — by design
   (G118), but it does mean a genuinely wrong record has to be fixed in the database by
   hand, with the audit trail recording that it happened.
22. **The assistant has never been called against the live API.** Every test mocks
   the SDK. The request shape, the refusal path and the error mapping are covered;
   what a real reply looks like is not.
23. **The assistant sends the operator's draft to Anthropic.** That is the feature,
   and it is the only place in this app where content leaves for a third party.
   It is stated on the composer and in the README rather than buried here.
24. **There is no spend limit.** Each press of *Suggest* is one API call at
   whatever it costs; nothing caps calls per hour or per month. For one operator
   pressing a button this is a small bill, and it is not a control.
25. **Suggestions accumulate until cleared.** They are per business, not per draft,
   so the composer shows the last set until *Clear suggestions* is pressed.
26. **The assistant cannot see the image**, only that one is attached. Captions are
   written from the draft text, never from what is actually in the picture.
27. **`ANTHROPIC_API_KEY` lives in the environment, not the Vault.** Consistent with
   `META_APP_SECRET`: the Vault holds per-account credentials, which multiply and
   are revoked one at a time. An app-level key is one value, rotated in one place.
28. **Only the Debian/Ubuntu path of `db:ensure` has actually been run.** The macOS
   (`brew services`) and Docker strategies are written and their parsers tested, but
   this environment has neither, so they are unexercised. If the first run on a Mac
   fails, that is where to look.
29. **`db:ensure` cannot fix a wrong `ADMIN_DATABASE_URL`.** It deliberately does not
   create roles, databases or containers — it starts a service that already exists,
   or explains what it tried.
