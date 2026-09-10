'use server'

import { cookies } from 'next/headers'
import { revalidatePath } from 'next/cache'

import { assertCsrf } from '@/lib/security/csrf'
import { requireMfaSessionOrThrow } from '@/lib/security/session'
import { recordAuditOrThrow } from '@/lib/audit'
import { ACTIVE_BUSINESS_COOKIE, UUID_PATTERN, activeBusinessCookieOptions } from '@/lib/business'
import { DASHBOARD_PATH } from '@/lib/security/routes'

export async function switchBusinessAction(formData: FormData): Promise<void> {
  await assertCsrf(formData)
  // Layer 2: this POST is routed to the page, not through a proxy-matched route of its own.
  const { supabase, userId } = await requireMfaSessionOrThrow()

  const businessId = String(formData.get('businessId') ?? '')
  if (!UUID_PATTERN.test(businessId)) throw new Error('Invalid business id')

  // Row level security makes this the membership check: a non-member gets no row.
  const { data, error } = await supabase
    .from('businesses')
    .select('id')
    .eq('id', businessId)
    .maybeSingle()

  if (error) throw new Error(`Could not verify membership: ${error.message}`)
  if (!data) throw new Error('You are not a member of that business')

  // Audited before the cookie is written. The reverse order meant a failing audit
  // write threw after the switch had already happened, leaving the mutation done
  // and unrecorded.
  await recordAuditOrThrow({
    action: 'business.switch',
    businessId,
    targetType: 'business',
    targetId: businessId,
    actorUserId: userId,
  })

  const cookieStore = await cookies()
  cookieStore.set(ACTIVE_BUSINESS_COOKIE, businessId, activeBusinessCookieOptions())

  revalidatePath(DASHBOARD_PATH)
}
