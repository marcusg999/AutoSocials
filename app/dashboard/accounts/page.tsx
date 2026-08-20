import { requireMfaSession } from '@/lib/security/session'

export const dynamic = 'force-dynamic'

export default async function AccountsPage() {
  // Layer 2. Even a placeholder page proves the session for itself.
  await requireMfaSession()

  return (
    <main>
      <h1>Accounts</h1>
      <p className="lede">Coming in a later phase.</p>
    </main>
  )
}
