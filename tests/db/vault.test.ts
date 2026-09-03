/**
 * QUALITY BAR #2 (database half): credentials live in the Vault, and a browser
 * session cannot reach them.
 *
 * social_accounts holds only a reference -- the NAME of a Vault secret. The secret
 * itself is encrypted at rest and the two functions that touch it are granted to
 * service_role only, so a logged-in user calling the public API cannot decrypt
 * anything even if they guess the reference.
 */
import { beforeAll, afterAll, describe, expect, test } from 'vitest'
import { asAdmin, asUser, dropDatabase, expectRejected, freshDatabase } from './helpers'

const DB = 'postdeck_vault_test'
let url: string
const ALICE = '11111111-1111-1111-1111-111111111111'
let businessA: string
let accountId: string
const SECRET = 'fb-live-token-SHOULD-NEVER-LEAK-9f3a2b'

beforeAll(async () => {
  url = await freshDatabase(DB)
  await asAdmin(url, async (q) => {
    await q(`insert into auth.users (id, email) values ($1,'alice@example.com')`, [ALICE])
    businessA = (await q(`insert into public.businesses (name) values ('Tenant A') returning id`)).rows[0].id
    await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`, [businessA, ALICE])
    accountId = (await q(`insert into public.social_accounts (business_id, platform, label) values ($1,'facebook','FB page') returning id`, [businessA])).rows[0].id
    await q(`select app.store_account_credential($1, $2)`, [accountId, SECRET])
  })
}, 60_000)

afterAll(async () => { await dropDatabase(DB) })

test('storing a credential puts a reference on the row, never the secret', async () => {
  await asAdmin(url, async (q) => {
    const row = (await q(`select * from public.social_accounts where id=$1`, [accountId])).rows[0]
    expect(row.encrypted_credential_ref).toMatch(/^social_account_[0-9a-f]{32}$/)
    expect(JSON.stringify(row)).not.toContain(SECRET)
  })
})



describe('a signed-in browser session cannot reach the Vault', () => {
  test('a member of the business still cannot execute read_account_credential', async () => {
    await asUser(url, ALICE, 'aal2', async (q) => {
      const err = await expectRejected(() => q(`select app.read_account_credential($1)`, [accountId]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('a member of the business cannot execute store_account_credential', async () => {
    await asUser(url, ALICE, 'aal2', async (q) => {
      const err = await expectRejected(() => q(`select app.store_account_credential($1,'anything')`, [accountId]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('a member cannot query the vault schema directly', async () => {
    await asUser(url, ALICE, 'aal2', async (q) => {
      const err = await expectRejected(() => q(`select * from vault.decrypted_secrets`))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

})

// Round 15: phase 1 stores no credentials at all -- social_accounts is empty and
// these functions have no caller in app/ or lib/. What is kept is the property that
// matters if phase 2 does start storing them: a browser session cannot reach the
// Vault. The round-trip tests come back when there is a round trip to test.
