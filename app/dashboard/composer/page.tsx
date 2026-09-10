import { csrfField } from '@/lib/security/csrf'
import { requireMfaSession } from '@/lib/security/session'
import { listBusinesses, resolveActiveBusiness, UUID_PATTERN } from '@/lib/business'
import { MAX_POST_TEXT, parsePostContent } from '@/lib/connectors/content'
import { defaultScheduleValue } from '@/lib/publishing/schedule-time'

import { isAssistantConfigured } from '@/lib/env'

import {
  discardSuggestionsAction, saveDraftAction, schedulePostAction, suggestPostAction,
} from './actions'

export const dynamic = 'force-dynamic'

export default async function ComposerPage({
  searchParams,
}: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  // Layer 2. The page establishes its own session rather than trusting the proxy.
  const { supabase } = await requireMfaSession()
  const params = await searchParams
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

  // Editing a draft. RLS decides whether this id is readable at all, so a draft id
  // belonging to someone else simply comes back empty.
  const draftId = String(params.draft ?? '')
  const { data: draft } = UUID_PATTERN.test(draftId)
    ? await supabase
      .from('posts')
      .select('id, business_id, status, body')
      .eq('id', draftId)
      .eq('status', 'draft')
      .maybeSingle()
    : { data: null }

  const editing = draft && draft.business_id === active?.id ? draft : null
  const content = parsePostContent(editing?.body)

  // What the assistant last proposed. Row level security scopes this to the
  // caller's businesses; the filter picks which of their own is on screen.
  const { data: suggestionRows } = await supabase
    .from('post_suggestions')
    .select('id, business_id, suggestion, model, created_at')
    .order('created_at', { ascending: true })

  const suggestions = (suggestionRows ?? []).filter((row) => row.business_id === active?.id)

  return (
    <main>
      <h1>{editing ? 'Edit draft' : 'Composer'}</h1>
      <p className="lede">
        Write a post and schedule it to the accounts connected to{' '}
        <strong>{active?.name ?? 'no business'}</strong>. All times UTC.
      </p>

      {params.saved ? <div className="panel">Draft saved.</div> : null}
      {params.suggested ? <div className="panel">Suggestions below.</div> : null}

      {!active ? (
        <div className="panel"><p className="muted">Pick a business first.</p></div>
      ) : (
        <form action={schedulePostAction} className="panel">
          {csrf}
          <input type="hidden" name="businessId" value={active.id} />
          {editing ? <input type="hidden" name="postId" value={editing.id} /> : null}

          <label htmlFor="text">Post</label>
          <textarea id="text" name="text" rows={6} maxLength={MAX_POST_TEXT}
            defaultValue={content.text} placeholder="What are you posting?" />
          <p className="muted">
            Up to {MAX_POST_TEXT} characters, which is Instagram&rsquo;s caption limit and the
            tightest of the two.
          </p>

          <label htmlFor="imageUrl">Image URL (optional for Facebook, required for Instagram)</label>
          <input id="imageUrl" name="imageUrl" type="url" defaultValue={content.imageUrl ?? ''}
            placeholder="https://example.com/photo.jpg" />
          <p className="muted">
            Meta fetches this address itself, so it has to be reachable from the internet — not
            from your own machine.
          </p>

          {connected.length === 0 ? (
            <p className="muted">
              No connected accounts yet, so this can only be saved as a draft. Connect one on the{' '}
              <a href="/dashboard/accounts">Accounts</a> page.
            </p>
          ) : (
            <>
              <label htmlFor="scheduledFor">When (UTC)</label>
              <input id="scheduledFor" name="scheduledFor" type="datetime-local" required
                defaultValue={defaultScheduleValue()} />
              <p className="muted">
                Times are UTC everywhere in this app, on this form and on the calendar. A time in
                the past means it goes out on the next worker run.
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
            </>
          )}

          {isAssistantConfigured() ? (
            <>
              <label htmlFor="instruction">Ask the assistant (optional)</label>
              <input id="instruction" name="instruction" type="text"
                placeholder="shorter, warmer, mention the opening hours" />
              <p className="muted">
                It rewrites the draft above and proposes alternatives. It cannot publish
                anything — every suggestion still has to be scheduled by you.
              </p>
            </>
          ) : null}

          <div className="actions">
            {connected.length > 0 ? <button type="submit">Schedule</button> : null}
            {/* Same form, different action: a draft keeps whatever is typed without
                needing an account, a time, or a post that passes platform rules. */}
            <button type="submit" formAction={saveDraftAction} className="secondary">
              {editing ? 'Save draft' : 'Save as draft'}
            </button>
            {isAssistantConfigured() ? (
              <button type="submit" formAction={suggestPostAction} className="secondary">
                Suggest
              </button>
            ) : null}
          </div>
        </form>
      )}

      {suggestions.length > 0 ? (
        <div className="panel">
          <h2>Suggestions</h2>
          <ul className="rows">
            {suggestions.map((row) => (
              <li key={row.id}>
                <span>
                  {row.suggestion}
                  <br />
                  <span className="muted">
                    {row.model} · {row.suggestion.length} characters
                  </span>
                </span>
                {/* Using one saves it as a draft rather than scheduling it, so the
                    assistant's text still passes through a human and a form. */}
                {active ? (
                  <form action={saveDraftAction} className="inline">
                    {csrf}
                    <input type="hidden" name="businessId" value={active.id} />
                    {editing ? <input type="hidden" name="postId" value={editing.id} /> : null}
                    <input type="hidden" name="text" value={row.suggestion} />
                    <input type="hidden" name="imageUrl" value={content.imageUrl ?? ''} />
                    <button type="submit" className="secondary">Use</button>
                  </form>
                ) : null}
              </li>
            ))}
          </ul>
          {active ? (
            <form action={discardSuggestionsAction} className="inline">
              {csrf}
              <input type="hidden" name="businessId" value={active.id} />
              <button type="submit" className="secondary">Clear suggestions</button>
            </form>
          ) : null}
        </div>
      ) : null}

      <p className="muted">
        <a href="/dashboard/drafts">Drafts</a> · <a href="/dashboard/calendar">Calendar</a>
      </p>
    </main>
  )
}
