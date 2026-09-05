import { csrfField } from '@/lib/security/csrf'
import { requireMfaSession } from '@/lib/security/session'
import { listBusinesses, resolveActiveBusiness } from '@/lib/business'
import { isMetaConfigured } from '@/lib/env'
import { CONNECTABLE_PLATFORMS } from '@/lib/connectors/platforms'

import { beginConnectAction, disconnectAccountAction } from './actions'

export const dynamic = 'force-dynamic'

export default async function AccountsPage({
  searchParams,
}: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  // Layer 2: the page establishes its own session rather than trusting the proxy.
  const { supabase } = await requireMfaSession()
  const params = await searchParams

  // Computed once: the map callbacks below are not async, and the same hidden
  // field is valid in every form on the page.
  const csrf = await csrfField()

  const businesses = await listBusinesses(supabase)
  const active = await resolveActiveBusiness(businesses)

  // Row level security scopes this to the businesses the caller belongs to. The
  // page does no filtering of its own, and the credential column is not selected —
  // it is outside the authenticated grant, so asking for it would fail anyway.
  const { data: accounts } = await supabase
    .from('social_accounts')
    .select('id, business_id, platform, label, status, connected_at, token_expires_at, scopes')
    .order('label')

  const forBusiness = (accounts ?? []).filter((a) => a.business_id === active?.id)

  return (
    <main>
      <h1>Accounts</h1>
      <p className="lede">
        Social accounts connected to <strong>{active?.name ?? 'no business'}</strong>. The list is
        filtered by the database, not by this page.
      </p>

      {params.error ? <div className="panel error">Could not connect: {String(params.error)}</div> : null}
      {params.connected ? (
        <div className="panel">Connected {String(params.connected)} account(s).</div>
      ) : null}

      {!isMetaConfigured() ? (
        <div className="panel">
          <p className="muted">
            No Meta app is configured. Set <code>META_APP_ID</code> and <code>META_APP_SECRET</code> in
            <code>.env.local</code> — see the README for what to register.
          </p>
        </div>
      ) : active ? (
        <div className="panel">
          {CONNECTABLE_PLATFORMS.map((platform) => (
            <form action={beginConnectAction} key={platform} className="inline">
              {csrf}
              <input type="hidden" name="businessId" value={active.id} />
              <input type="hidden" name="platform" value={platform} />
              <button type="submit">Connect {platform}</button>
            </form>
          ))}
        </div>
      ) : null}

      <div className="panel">
        {forBusiness.length === 0 ? (
          <p className="muted">No accounts connected yet.</p>
        ) : (
          <ul className="rows">
            {forBusiness.map((account) => (
              <li key={account.id}>
                <span>
                  {account.label} <span className="muted">— {account.platform}</span>
                  {account.status === 'connected' ? <span className="badge">Connected</span> : null}
                  {account.token_expires_at ? (
                    <span className="muted"> · expires {new Date(account.token_expires_at).toDateString()}</span>
                  ) : null}
                </span>
                <form action={disconnectAccountAction} className="inline">
                  {csrf}
                  <input type="hidden" name="accountId" value={account.id} />
                  <button type="submit">Disconnect</button>
                </form>
              </li>
            ))}
          </ul>
        )}
      </div>
    </main>
  )
}
