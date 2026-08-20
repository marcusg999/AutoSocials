import { redirect } from 'next/navigation'

import { DASHBOARD_PATH } from '@/lib/security/routes'

export const dynamic = 'force-dynamic'

export default function HomePage() {
  redirect(DASHBOARD_PATH)
}
