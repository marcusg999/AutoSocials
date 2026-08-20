import 'server-only'

import { headers } from 'next/headers'
import type { SupabaseClient } from '@supabase/supabase-js'

import { createSupabaseServerClient } from '@/lib/supabase/server'
import { createSupabaseAdminClient } from '@/lib/supabase/admin'

export type AuditEntry = {
  action: string
  businessId?: string | null
  targetType?: string | null
  targetId?: string | null
  metadata?: Record<string, unknown>
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

async function write(supabase: SupabaseClient, entry: AuditEntry, ip: string | null): Promise<void> {
  // app.write_audit stamps the actor from the JWT itself, so a caller can never
  // forge whose action this was.
  const { error } = await supabase.schema('app').rpc('write_audit', {
    p_action: entry.action,
    p_business_id: entry.businessId ?? null,
    p_target_type: entry.targetType ?? null,
    p_target_id: entry.targetId ?? null,
    p_metadata: entry.metadata ?? {},
    p_ip: ip,
  })

  if (error) {
    // A lost audit row must never take a user-facing request down with it, but it
    // does need to be loud in the server logs.
    console.error('[audit] failed to record %s: %s', entry.action, error.message)
  }
}

/**
 * Records an action taken by the signed-in user. Pass the client you already have
 * when the session was created moments ago, so the audit row is written under it.
 */
export async function recordAudit(entry: AuditEntry, client?: SupabaseClient): Promise<void> {
  try {
    const supabase = client ?? (await createSupabaseServerClient())
    await write(supabase, entry, await clientIp())
  } catch (error) {
    console.error('[audit] failed to record %s: %o', entry.action, error)
  }
}

/**
 * Records an action where there is no session to record it under — in practice
 * only a failed login. Uses the service role client, so the actor comes out null.
 */
export async function recordAnonymousAudit(entry: AuditEntry): Promise<void> {
  try {
    const supabase = createSupabaseAdminClient()
    await write(supabase, entry, await clientIp())
  } catch (error) {
    console.error('[audit] failed to record %s: %o', entry.action, error)
  }
}
