import type { ReactNode } from 'react'
import Link from 'next/link'

import { csrfField } from '@/lib/security/csrf'
import { requireMfaSession } from '@/lib/security/session'
import { signOutAction } from '@/app/actions'

export const dynamic = 'force-dynamic'

export default async function DashboardLayout({ children }: { children: ReactNode }) {
  // Layer 2 for everything nested below. Each page repeats it for itself.
  const { email } = await requireMfaSession()

  return (
    <div className="shell">
      <nav className="nav">
        <span className="brand" style={{ margin: 0 }}>
          PostDeck
        </span>
        <Link href="/dashboard">Overview</Link>
        <Link href="/dashboard/composer">Composer</Link>
        <Link href="/dashboard/drafts">Drafts</Link>
        <Link href="/dashboard/calendar">Calendar</Link>
        <Link href="/dashboard/accounts">Accounts</Link>
        <span className="spacer" />
        <span className="muted">{email}</span>
        <form action={signOutAction}>
          {await csrfField()}
          <button type="submit" className="secondary">
            Sign out
          </button>
        </form>
      </nav>
      {children}
    </div>
  )
}
