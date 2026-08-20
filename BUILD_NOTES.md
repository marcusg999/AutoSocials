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
