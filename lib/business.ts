import 'server-only'

import { cookies } from 'next/headers'
import type { SupabaseClient } from '@supabase/supabase-js'

import { isProduction } from '@/lib/env'

// __Host- in production, matching the CSRF cookie: a browser will only accept it
// from a secure origin, for path '/', with no Domain attribute, so no sibling or
// parent subdomain can plant it. The value is re-validated against the RLS-filtered
// business list on every read anyway, but there is no reason to leave it writable.
export const ACTIVE_BUSINESS_COOKIE =
  process.env.NODE_ENV === 'production' ? '__Host-pd_active_business' : 'pd_active_business'

export type Business = {
  id: string
  name: string
  timezone: string
}

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export function activeBusinessCookieOptions() {
  return {
    httpOnly: true,
    secure: isProduction(),
    sameSite: 'lax' as const,
    path: '/',
  }
}

/**
 * No filter is applied here on purpose: row level security already restricts this
 * to businesses the caller is a member of.
 */
export async function listBusinesses(supabase: SupabaseClient): Promise<Business[]> {
  const { data, error } = await supabase
    .from('businesses')
    .select('id, name, timezone')
    .order('name', { ascending: true })

  if (error) throw new Error(`Could not load businesses: ${error.message}`)
  return (data ?? []) as Business[]
}

/**
 * The cookie is only a hint. It is accepted only when it names a business that
 * came back from the RLS-filtered list, so a tampered cookie selects nothing.
 */
export async function resolveActiveBusiness(businesses: Business[]): Promise<Business | null> {
  const cookieStore = await cookies()
  const requested = cookieStore.get(ACTIVE_BUSINESS_COOKIE)?.value
  const match = requested ? businesses.find((business) => business.id === requested) : undefined
  return match ?? businesses[0] ?? null
}
