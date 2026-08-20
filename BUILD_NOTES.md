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

## Known, accepted limitations

Stated plainly rather than left to be discovered.

1. **The MFA round trip has never run against a live Supabase project.** No project
   or credentials were available in this environment. The enrol/challenge/verify
   call shapes were written against the current documented API and the failure paths
   are tested, but the successful round trip is unproven. This is the single largest
   untested surface in the phase.
2. **The Vault used in tests is a pgcrypto stand-in**, not the real Supabase Vault.
   Call shapes match; the encryption does not.
3. **Audit writes are best-effort.** A failed audit write is logged and does not fail
   the user's request. That is a deliberate availability choice, but it means audit
   coverage is guaranteed for anything the database triggers see and best-effort for
   app-level events such as login.
4. **Failed-login audit rows record the attempted email address.** Deliberate — you
   cannot spot credential stuffing without it — but it is personal data in a table
   that by design can never be deleted.
5. **A user removed from a business keeps read access to their own historical audit
   rows** in that business, via the `actor_user_id = auth.uid()` branch of
   `audit_select_own`.
6. **`assertCsrf` trusts `x-forwarded-host` over `host`**, matching Next.js's own
   server-action origin check. This assumes deployment behind a proxy that
   overwrites that header. The synchroniser token, not the origin check, is the real
   defence.
7. **MFA enrolment issues a fresh factor on each render of the enrol page**, so a
   mistyped code means rescanning the QR code. Fixing this properly needs either
   client-side form state or a persisted pending factor.
