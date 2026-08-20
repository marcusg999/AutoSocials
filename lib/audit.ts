import 'server-only'

import { headers } from 'next/headers'

import { createSupabaseAdminClient } from '@/lib/supabase/admin'

export type AuditEntry = {
  action: string
  businessId?: string | null
  targetType?: string | null
  targetId?: string | null
  metadata?: Record<string, unknown>
  /** The user this action belongs to. Established by requireMfaSession(), never by the browser. */
  actorUserId?: string | null
}

/**
 * Best-effort read of the caller's address. Everything after the first entry of
 * X-Forwarded-For was appended by upstream proxies we do not control, so only the
 * first hop is recorded, and only if it parses as an address the `inet` column accepts.
 */
export async function clientIp(): Promise<string | null> {
  const headerList = await headers()
  const forwarded = headerList.get('x-forwarded-for')
  const candidate = forwarded?.split(',')[0]?.trim() ?? headerList.get('x-real-ip')?.trim() ?? null
  if (!candidate) return null

  // Strip an IPv4 port suffix such as "203.0.113.4:51234".
  const withoutPort = /^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(candidate)
    ? candidate.split(':')[0]!
    : candidate

  return /^[0-9a-fA-F:.]+$/.test(withoutPort) ? withoutPort : null
}

/**
 * Appends one audit_log row.
 *
 * This always goes through the service-role client, on our own server, and never
 * through the user's session. That is deliberate:
 *
 *   - app.write_audit is SECURITY DEFINER, so it writes past row level security.
 *     If it were callable by `authenticated`, any signed-in user could write
 *     permanent, undeletable rows into any tenant's audit trail with a forged
 *     action and a forged IP. It is granted to service_role only.
 *   - Only our server knows the true client IP, from the proxy headers. A value
 *     supplied by the browser would be worthless in an audit log.
 *   - The actor comes from the session we already verified with requireMfaSession(),
 *     not from the request body. And the database independently prefers auth.uid()
 *     over the actor we pass, so impersonation is impossible even from here.
 */
export async function recordAudit(entry: AuditEntry): Promise<void> {
  try {
    const supabase = createSupabaseAdminClient()
    const { error } = await supabase.schema('app').rpc('write_audit', {
      p_action: entry.action,
      p_business_id: entry.businessId ?? null,
      p_target_type: entry.targetType ?? null,
      p_target_id: entry.targetId ?? null,
      p_metadata: entry.metadata ?? {},
      p_ip: await clientIp(),
      p_actor_user_id: entry.actorUserId ?? null,
    })

    if (error) {
      // A lost audit row must never take a user-facing request down with it, but
      // it does need to be loud in the server logs.
      console.error('[audit] failed to record %s: %s', entry.action, error.message)
    }
  } catch (error) {
    console.error('[audit] failed to record %s: %o', entry.action, error)
  }
}

/**
 * Records an action where there is no session at all — in practice only a failed
 * login. The actor is whatever user id we could resolve for the attempted email,
 * or null if the account does not exist.
 */
export async function recordAnonymousAudit(entry: AuditEntry): Promise<void> {
  await recordAudit(entry)
}
