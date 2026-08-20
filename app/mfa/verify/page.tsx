import { redirect } from 'next/navigation'

import { csrfField } from '@/lib/security/csrf'
import { resolveSessionState } from '@/lib/security/session'
import { DASHBOARD_PATH, LOGIN_PATH, MFA_ENROLL_PATH } from '@/lib/security/routes'
import { signOutAction } from '@/app/actions'

import { verifyFactorAction } from './actions'

export const dynamic = 'force-dynamic'

const MESSAGES: Record<string, string> = {
  code_format: 'Enter the six digits shown in your authenticator app.',
  invalid_code: 'That code was not accepted. Wait for the next one and try again.',
  unknown_factor: 'That authenticator is no longer registered.',
  challenge_failed: 'The authenticator challenge could not be started. Try again.',
}

export default async function VerifyPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>
}) {
  // Layer 2, independent of the proxy.
  const state = await resolveSessionState()
  if (state.status === 'anonymous') redirect(LOGIN_PATH)
  if (state.status === 'verified') redirect(DASHBOARD_PATH)
  if (state.status === 'needs-enrollment') redirect(MFA_ENROLL_PATH)

  const { supabase } = state
  const { error } = await searchParams
  const message = error ? MESSAGES[error] ?? 'Verification could not be completed.' : null

  const { data: factors } = await supabase.auth.mfa.listFactors()
  const factor = factors?.totp[0]
  if (!factor) redirect(MFA_ENROLL_PATH)

  return (
    <main className="shell narrow">
      <p className="brand">PostDeck</p>
      <h1>Two-factor check</h1>
      <p className="lede">Enter the current code from your authenticator app.</p>

      {message ? <p className="alert">{message}</p> : null}

      <form action={verifyFactorAction} className="panel">
        {await csrfField()}
        <input type="hidden" name="factorId" value={factor.id} />
        <div className="field">
          <label htmlFor="code">Six-digit code</label>
          <input
            id="code"
            name="code"
            className="code-input"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            autoFocus
            required
          />
        </div>
        <button type="submit">Verify</button>
      </form>

      <form action={signOutAction}>
        {await csrfField()}
        <button type="submit" className="secondary">
          Sign out
        </button>
      </form>
    </main>
  )
}
