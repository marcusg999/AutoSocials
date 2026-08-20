/**
 * Creates the single administrator and makes them a member of all seven businesses.
 *
 * Run once, against a real Supabase project, after `npm run db:up`:
 *
 *   ADMIN_EMAIL=you@example.com ADMIN_PASSWORD='...' npx tsx scripts/seed-admin.ts
 *
 * The password is read from the environment and never written to disk or to git.
 * The admin still has to enrol TOTP on first sign-in: this script deliberately does
 * NOT create an MFA factor, because a factor the server generated is not a second
 * factor the user possesses.
 */
import { createClient } from '@supabase/supabase-js'

const url = process.env.SUPABASE_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY
const email = process.env.ADMIN_EMAIL
const password = process.env.ADMIN_PASSWORD

if (!url || !serviceRoleKey) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required')
if (!email || !password) throw new Error('ADMIN_EMAIL and ADMIN_PASSWORD are required')
if (password.length < 12) throw new Error('ADMIN_PASSWORD must be at least 12 characters')

// The service-role client bypasses RLS. It exists only in this script and on the
// server; it is never imported by anything the browser can reach.
const admin = createClient(url, serviceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
})

async function main() {
  const { data: existing } = await admin.auth.admin.listUsers()
  const already = existing?.users.find((u) => u.email?.toLowerCase() === email!.toLowerCase())

  if (already) {
    console.log(`admin ${email} already exists (${already.id})`)
  } else {
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    })
    if (error) throw error
    console.log(`created admin ${email} (${data.user.id})`)
  }

  // app.grant_admin_all_businesses is granted to service_role only.
  const { data: added, error: rpcError } = await admin.schema('app').rpc('grant_admin_all_businesses', {
    admin_email: email,
  })
  if (rpcError) throw rpcError
  console.log(`admin is now an owner of all businesses (${added} membership rows added)`)
  console.log('\nNext: sign in at /login. You will be required to enrol TOTP before anything else loads.')
}

main().catch((err) => {
  console.error(err.message ?? err)
  process.exit(1)
})
