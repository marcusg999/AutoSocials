import { csrfField } from '@/lib/security/csrf'
import { requireMfaSession } from '@/lib/security/session'
import { listBusinesses, resolveActiveBusiness } from '@/lib/business'
import { parsePostContent } from '@/lib/connectors/content'
import { formatUtc } from '@/lib/publishing/schedule-time'

import { deleteDraftAction } from '../composer/actions'

export const dynamic = 'force-dynamic'

/** Enough of a post to recognise it, not enough to read it twice. */
function preview(body: unknown): string {
  const content = parsePostContent(body)
  if (content.text.trim() === '') return content.imageUrl ? '(image only)' : '(empty)'
  return content.text.length > 120 ? `${content.text.slice(0, 120)}…` : content.text
}

export default async function DraftsPage({
  searchParams,
}: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  // Layer 2. The page establishes its own session rather than trusting the proxy.
  const { supabase } = await requireMfaSession()
  const params = await searchParams
  const csrf = await csrfField()

  const businesses = await listBusinesses(supabase)
  const active = await resolveActiveBusiness(businesses)

  // Row level security returns only the caller's posts; the filter below picks
  // which of their own businesses is on screen.
  const { data: rows } = await supabase
    .from('posts')
    .select('id, business_id, body, created_at')
    .eq('status', 'draft')
    .order('created_at', { ascending: false })

  const drafts = (rows ?? []).filter((row) => row.business_id === active?.id)

  return (
    <main>
      <h1>Drafts</h1>
      <p className="lede">
        Posts saved for <strong>{active?.name ?? 'no business'}</strong> that have not been
        scheduled to anything yet.
      </p>

      {params.deleted ? <div className="panel">Draft deleted.</div> : null}

      <div className="panel">
        {drafts.length === 0 ? (
          <p className="muted">
            No drafts. Anything you save in the <a href="/dashboard/composer">Composer</a> without
            scheduling it appears here.
          </p>
        ) : (
          <ul className="rows">
            {drafts.map((draft) => (
              <li key={draft.id}>
                <span>
                  {preview(draft.body)}
                  <br />
                  <span className="muted">saved {formatUtc(draft.created_at)}</span>
                </span>
                <span className="actions">
                  <a href={`/dashboard/composer?draft=${draft.id}`}>Edit</a>
                  <form action={deleteDraftAction} className="inline">
                    {csrf}
                    <input type="hidden" name="postId" value={draft.id} />
                    <button type="submit" className="secondary">Delete</button>
                  </form>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </main>
  )
}
