'use server'

import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'

import { assertCsrf } from '@/lib/security/csrf'
import { requireMfaSessionOrThrow } from '@/lib/security/session'
import { recordAuditOrThrow } from '@/lib/audit'
import { UUID_PATTERN } from '@/lib/business'
import { contentProblemFor, MAX_POST_TEXT, type PostContent } from '@/lib/connectors/content'
import { parseScheduledFor } from '@/lib/publishing/schedule-time'
import type { SocialPlatform } from '@/lib/connectors/platforms'

/**
 * Write a post and schedule it to one or more connected accounts.
 *
 * Everything here goes through the caller's own session, so row level security is
 * doing the tenancy work rather than a filter in this file: reading the accounts
 * returns only the caller's, and both inserts are checked again by policy on the
 * way in. The explicit checks below are for things RLS cannot express — that the
 * chosen accounts are actually connected, and that the content is something the
 * chosen platforms will accept.
 */
export async function schedulePostAction(formData: FormData): Promise<void> {
  await assertCsrf(formData)
  const { supabase, userId } = await requireMfaSessionOrThrow()

  const businessId = String(formData.get('businessId') ?? '')
  if (!UUID_PATTERN.test(businessId)) throw new Error('Invalid business id')

  const accountIds = formData.getAll('accountIds').map(String).filter((id) => UUID_PATTERN.test(id))
  if (accountIds.length === 0) throw new Error('Pick at least one account to post to')

  const content: PostContent = {
    text: String(formData.get('text') ?? '').slice(0, MAX_POST_TEXT + 1),
    imageUrl: String(formData.get('imageUrl') ?? '').trim() || null,
  }

  const when = parseScheduledFor(String(formData.get('scheduledFor') ?? ''))
  if (!when) throw new Error('That is not a valid date and time')

  // RLS scopes this to accounts the caller can see, so an id belonging to another
  // tenant simply is not in the result and fails the count check below.
  const { data: accounts, error } = await supabase
    .from('social_accounts')
    .select('id, platform, label, status, business_id')
    .in('id', accountIds)
  if (error) throw new Error(`Could not read the accounts: ${error.message}`)

  const chosen = accounts ?? []
  if (chosen.length !== accountIds.length) {
    throw new Error('One of those accounts does not exist, or is not yours')
  }
  // Belt and braces over the policy: the scheduled_posts insert policy also
  // requires the account to sit in this business, so this is the message rather
  // than the control.
  if (chosen.some((account) => account.business_id !== businessId)) {
    throw new Error('One of those accounts belongs to a different business')
  }
  const disconnected = chosen.filter((account) => account.status !== 'connected')
  if (disconnected.length > 0) {
    throw new Error(`Not connected: ${disconnected.map((a) => a.label).join(', ')}`)
  }

  // Per platform, while a human is still here to fix it. The connector checks this
  // again at publish time, but by then the answer arrives as a failed row hours
  // later — which is exactly the experience this is here to avoid.
  for (const account of chosen) {
    const problem = contentProblemFor(account.platform as SocialPlatform, content)
    if (problem) throw new Error(`${account.label}: ${problem}`)
  }

  const { data: post, error: postError } = await supabase
    .from('posts')
    .insert({
      business_id: businessId,
      // The insert policy requires this to be the caller. It comes from the session
      // we established, never from the form.
      created_by: userId,
      status: 'scheduled',
      body: { text: content.text, imageUrl: content.imageUrl },
    })
    .select('id')
    .single()
  if (postError || !post) throw new Error(`Could not save the post: ${postError?.message}`)

  const { error: scheduleError } = await supabase.from('scheduled_posts').insert(
    chosen.map((account) => ({
      post_id: post.id,
      social_account_id: account.id,
      business_id: businessId,
      scheduled_for: when.toISOString(),
      status: 'scheduled' as const,
    })))
  if (scheduleError) throw new Error(`Could not schedule the post: ${scheduleError.message}`)

  await recordAuditOrThrow({
    action: 'post.scheduled',
    businessId,
    targetType: 'post',
    targetId: post.id,
    // Counts and platforms, never the post text: audit_log can never be pruned, and
    // there is no reason for it to hold a second copy of everything ever written.
    metadata: {
      accounts: chosen.length,
      platforms: [...new Set(chosen.map((a) => a.platform))],
      scheduled_for: when.toISOString(),
      has_image: Boolean(content.imageUrl),
    },
    actorUserId: userId,
  })

  revalidatePath('/dashboard/calendar')
  redirect('/dashboard/calendar?scheduled=1')
}

/**
 * Cancel one scheduled post.
 *
 * A DELETE, which is what the narrowed grant from 0014 leaves a human: they may
 * move a post in time or call it off, but they cannot declare it published.
 */
export async function cancelScheduledPostAction(formData: FormData): Promise<void> {
  await assertCsrf(formData)
  const { supabase, userId } = await requireMfaSessionOrThrow()

  const scheduledId = String(formData.get('scheduledId') ?? '')
  if (!UUID_PATTERN.test(scheduledId)) throw new Error('Invalid scheduled post id')

  const { data, error } = await supabase
    .from('scheduled_posts')
    .select('id, business_id, status')
    .eq('id', scheduledId)
    .maybeSingle()
  if (error) throw new Error(`Could not read that scheduled post: ${error.message}`)
  if (!data) throw new Error('No such scheduled post')

  // Cancelling something already published would delete the only local record that
  // it went out, while the post itself stays up. Refuse: it is not a cancellation,
  // it is losing the receipt.
  if (data.status === 'published') {
    throw new Error('That one has already been published; cancelling it would only lose the record')
  }

  await recordAuditOrThrow({
    action: 'post.schedule.cancelled',
    businessId: data.business_id,
    targetType: 'scheduled_post',
    targetId: scheduledId,
    actorUserId: userId,
  })

  const { error: deleteError } = await supabase
    .from('scheduled_posts').delete().eq('id', scheduledId)
  if (deleteError) throw new Error(`Could not cancel it: ${deleteError.message}`)

  revalidatePath('/dashboard/calendar')
}
