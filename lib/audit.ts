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
 * The caller's address, taken from the END of X-Forwarded-For.
 *
 * This is the opposite of the obvious choice and the reason matters. An appending
 * proxy (nginx's proxy_add_x_forwarded_for, an ALB, HAProxy) produces
 * `<whatever the client sent>, <the address the proxy actually saw>`. Taking
 * entry [0] therefore records a value the client chose -- on exactly the
 * failed-login rows whose purpose is spotting credential stuffing.
 *
 * TRUSTED_PROXY_COUNT says how many hops we control. The address we want is that
 * many entries from the end.
 */
export async function clientIp(): Promise<string | null> {
  const headerList = await headers()
  const forwarded = headerList.get('x-forwarded-for')

  let candidate: string | null = null
  if (forwarded) {
    const hops = forwarded.split(',').map((hop) => hop.trim()).filter(Boolean)
    const trusted = Number(process.env.TRUSTED_PROXY_COUNT ?? '1')
    const index = hops.length - Math.max(1, Number.isFinite(trusted) ? trusted : 1)
    candidate = hops[Math.max(0, index)] ?? null
  }
  candidate ??= headerList.get('x-real-ip')?.trim() ?? null
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
    await writeAuditRow(entry)
  } catch (error) {
    // A lost audit row must never take an ordinary request down with it, but it
    // does need to be loud in the server logs.
    console.error('[audit] failed to record %s: %o', entry.action, error)
  }
}

/**
 * Records an action whose audit row is part of the security control itself, not
 * merely a nice-to-have: signing in, MFA enrolment, MFA verification, switching
 * business. If the row cannot be written the action FAILS.
 *
 * The trade is deliberate. Everywhere else a dropped audit row costs visibility;
 * here it would mean an authentication event happened with no record of it, which
 * is precisely the event an attacker most wants unlogged. "Every mutating action
 * writes an audit row" has to mean writes, not attempts.
 */
export async function recordAuditOrThrow(entry: AuditEntry): Promise<void> {
  await writeAuditRow(entry)
}

async function writeAuditRow(entry: AuditEntry): Promise<void> {
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

  if (error) throw new Error(`could not write audit row for ${entry.action}: ${error.message}`)
}

/**
 * Records an action where there is no session at all — in practice only a failed
 * login. The actor is whatever user id we could resolve for the attempted email,
 * or null if the account does not exist.
 */
export async function recordAnonymousAudit(entry: AuditEntry): Promise<void> {
  await recordAuditOrThrow(entry)
}
