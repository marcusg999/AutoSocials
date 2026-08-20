import { csrfField } from '@/lib/security/csrf'
import { requireMfaSession } from '@/lib/security/session'
import { listBusinesses, resolveActiveBusiness } from '@/lib/business'

import { switchBusinessAction } from './actions'

export const dynamic = 'force-dynamic'

export default async function DashboardPage() {
  // Layer 2, repeated here rather than inherited from the layout.
  const { supabase } = await requireMfaSession()

  const businesses = await listBusinesses(supabase)
  const active = await resolveActiveBusiness(businesses)

  return (
    <main>
      <h1>Businesses</h1>
      <p className="lede">
        These are the businesses you are a member of. The list is filtered by the database, not by
        this page.
      </p>

      {businesses.length === 0 ? (
        <div className="panel">
          <p className="muted">
            You are not a member of any business yet. An owner needs to add you before anything
            appears here.
          </p>
        </div>
      ) : (
        <>
          <form action={switchBusinessAction} className="panel switcher">
            {await csrfField()}
            <div className="field">
              <label htmlFor="businessId">Active business</label>
              <select id="businessId" name="businessId" defaultValue={active?.id ?? ''}>
                {businesses.map((business) => (
                  <option key={business.id} value={business.id}>
                    {business.name}
                  </option>
                ))}
              </select>
            </div>
            <button type="submit">Switch</button>
          </form>

          <div className="panel">
            <ul className="rows">
              {businesses.map((business) => (
                <li key={business.id}>
                  <span>
                    {business.name} <span className="muted">— {business.timezone}</span>
                  </span>
                  {business.id === active?.id ? <span className="badge">Active</span> : null}
                </li>
              ))}
            </ul>
          </div>
        </>
      )}
    </main>
  )
}
