import 'server-only'

import { createSupabaseAdminClient } from '@/lib/supabase/admin'
import { connectorFor } from '@/lib/connectors/service'
import { parsePostContent } from '@/lib/connectors/content'
import type { SocialPlatform } from '@/lib/connectors/platforms'

/**
 * The publisher: take due work, do it once, record what happened.
 *
 * This runs as service_role, off the back of no request at all, which makes it the
 * one place in this codebase with no user session to lean on. Everything it is
 * allowed to do is therefore decided by the two database functions it calls:
 * app.claim_due_scheduled_posts hands it work, and app.complete_scheduled_post
 * records the outcome. It has no other route to a scheduled post's state.
 *
 * The credential is read here and passed straight to a connector. It is never
 * returned, never logged, and — see redactCredential — deliberately scrubbed out of
 * provider error text before that text is written to a column the operator reads.
 */

/** One row the claim handed us. Mirrors the function's return type. */
interface ClaimedPost {
  scheduled_id: string
  business_id: string
  post_id: string
  social_account_id: string
  platform: SocialPlatform
  provider_account_ref: string | null
  body: unknown
  attempts: number
}

export interface PublishRunResult {
  claimed: number
  published: number
  failed: number
}

export interface PublishRunOptions {
  /** Identifies the worker in locked_by. Diagnostic; correctness comes from the lease. */
  worker?: string
  batch?: number
  /** How long a claim is held before another worker may take the row back. */
  leaseMinutes?: number
  maxAttempts?: number
}

export async function publishDuePosts(
  options: PublishRunOptions = {},
): Promise<PublishRunResult> {
  const worker = options.worker ?? defaultWorkerName()
  const batch = options.batch ?? 10
  const leaseMinutes = options.leaseMinutes ?? 5
  const maxAttempts = options.maxAttempts ?? 5

  const admin = createSupabaseAdminClient()

  const { data, error } = await admin.schema('app').rpc('claim_due_scheduled_posts', {
    p_worker: worker,
    p_batch: batch,
    p_lease: `${leaseMinutes} minutes`,
  })
  if (error) throw new Error(`Could not claim scheduled posts: ${error.message}`)

  const claimed = (data ?? []) as ClaimedPost[]
  const result: PublishRunResult = { claimed: claimed.length, published: 0, failed: 0 }

  for (const row of claimed) {
    // One row's failure must not abandon the rest of the batch. Anything left
    // unfinished stays leased until it expires, which delays it by the lease rather
    // than losing it — but there is no reason to make the other nine wait.
    const outcome = await publishOne(admin, row)
    if (outcome.ok) result.published += 1
    else result.failed += 1

    const { error: completeError } = await admin.schema('app').rpc('complete_scheduled_post', {
      p_scheduled_id: row.scheduled_id,
      p_ok: outcome.ok,
      p_provider_post_ref: outcome.ok ? outcome.providerPostRef : null,
      p_error: outcome.ok ? null : outcome.error,
      p_max_attempts: maxAttempts,
    })
    // If we cannot record the outcome there is nothing useful left to do about this
    // row: the post may already be live, so retrying the publish would be worse
    // than leaving the lease to expire. Surfacing it stops the run quietly
    // succeeding while its results went nowhere.
    if (completeError) {
      throw new Error(
        `Published state could not be recorded for ${row.scheduled_id}: ${completeError.message}`)
    }
  }

  return result
}

type Outcome =
  | { ok: true; providerPostRef: string }
  | { ok: false; error: string }

async function publishOne(
  admin: ReturnType<typeof createSupabaseAdminClient>,
  row: ClaimedPost,
): Promise<Outcome> {
  let credential: string | null = null
  try {
    if (!row.provider_account_ref) {
      return { ok: false, error: 'The account has no provider reference; reconnect it.' }
    }

    const { data, error } = await admin.schema('app')
      .rpc('read_account_credential', { target_account_id: row.social_account_id })
    if (error) return { ok: false, error: `Could not read the credential: ${error.message}` }
    credential = data ? String(data) : null
    if (!credential) {
      return { ok: false, error: 'No stored credential for that account; reconnect it.' }
    }

    const content = parsePostContent(row.body)
    const providerPostRef = await connectorFor(row.platform)
      .publish(credential, row.provider_account_ref, content)

    return { ok: true, providerPostRef }
  } catch (thrown) {
    const message = thrown instanceof Error ? thrown.message : String(thrown)
    return { ok: false, error: redactCredential(message, credential) }
  }
}

/**
 * Provider error text is about to be written to last_error, which the calendar
 * shows to the operator and which lives in an append-only table.
 *
 * The connectors already avoid echoing the token, so this is the second fence and
 * not the first. It exists because the cost of being wrong is asymmetric: a
 * redacted message is mildly annoying, whereas a Page token written into a row
 * that by design can never be deleted is a credential we cannot take back.
 */
export function redactCredential(message: string, credential: string | null): string {
  if (!credential || credential.length < 8) return message
  return message.split(credential).join('[redacted credential]')
}

function defaultWorkerName(): string {
  return `${process.env.PUBLISH_WORKER_ID ?? 'worker'}-${process.pid}`
}
