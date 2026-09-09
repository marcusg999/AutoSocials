import { csrfField } from '@/lib/security/csrf'
import { requireMfaSession } from '@/lib/security/session'
import { listBusinesses, resolveActiveBusiness } from '@/lib/business'
import { MAX_POST_TEXT } from '@/lib/connectors/content'
import { defaultScheduleValue } from '@/lib/publishing/schedule-time'

import { schedulePostAction } from './actions'

export const dynamic = 'force-dynamic'

export default async function ComposerPage() {
  // Layer 2. The page establishes its own session rather than trusting the proxy.
  const { supabase } = await requireMfaSession()
  const csrf = await csrfField()

  const businesses = await listBusinesses(supabase)
  const active = await resolveActiveBusiness(businesses)

  // Row level security scopes this to the caller's businesses; the filter below is
  // only picking which of their own businesses is on screen.
  const { data: accounts } = await supabase
    .from('social_accounts')
    .select('id, business_id, platform, label, status')
    .eq('status', 'connected')
    .order('label')

  const connected = (accounts ?? []).filter((a) => a.business_id === active?.id)

  return (
    <main>
      <h1>Composer</h1>
      <p className="lede">
        Write a post and schedule it to the accounts connected to{' '}
        <strong>{active?.name ?? 'no business'}</strong>.
      </p>

      {!active ? (
        <div className="panel"><p className="muted">Pick a business first.</p></div>
      ) : connected.length === 0 ? (
        <div className="panel">
          <p className="muted">
            No connected accounts yet. Connect one on the <a href="/dashboard/accounts">Accounts</a>{' '}
            page and it will appear here.
          </p>
        </div>
      ) : (
        <form action={schedulePostAction} className="panel">
          {csrf}
          <input type="hidden" name="businessId" value={active.id} />

          <label htmlFor="text">Post</label>
          <textarea id="text" name="text" rows={6} maxLength={MAX_POST_TEXT}
            placeholder="What are you posting?" />

          <label htmlFor="imageUrl">Image URL (optional for Facebook, required for Instagram)</label>
          <input id="imageUrl" name="imageUrl" type="url" placeholder="https://example.com/photo.jpg" />
          <p className="muted">
            Meta fetches this address itself, so it has to be reachable from the internet — not
            from your own machine.
          </p>

          <label htmlFor="scheduledFor">When (UTC)</label>
          <input id="scheduledFor" name="scheduledFor" type="datetime-local" required
            defaultValue={defaultScheduleValue()} />
          <p className="muted">
            Times are UTC everywhere in this app, on this form and on the calendar. A time in the
            past means it goes out on the next worker run.
          </p>

          <fieldset>
            <legend>Post to</legend>
            {connected.map((account) => (
              <label key={account.id} className="check">
                <input type="checkbox" name="accountIds" value={account.id} />
                {account.label} <span className="muted">— {account.platform}</span>
              </label>
            ))}
          </fieldset>

          <button type="submit">Schedule</button>
        </form>
      )}
    </main>
  )
}
