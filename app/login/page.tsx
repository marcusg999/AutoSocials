import { csrfField } from '@/lib/security/csrf'

import { signInAction } from './actions'

export const dynamic = 'force-dynamic'

const MESSAGES: Record<string, string> = {
  invalid: 'Email or password is not correct.',
  missing: 'Enter both an email address and a password.',
  signed_out: 'You have been signed out.',
  exchange_failed: 'That sign-in link could not be used. Try again.',
  missing_code: 'That sign-in link was incomplete. Try again.',
}

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>
}) {
  const { error } = await searchParams
  const message = error ? MESSAGES[error] ?? 'Sign in could not be completed.' : null

  return (
    <main className="shell narrow">
      <p className="brand">PostDeck</p>
      <h1>Sign in</h1>
      <p className="lede">Every account is protected by an authenticator app.</p>

      {message ? <p className="alert">{message}</p> : null}

      <form action={signInAction} className="panel">
        {await csrfField()}
        <div className="field">
          <label htmlFor="email">Email address</label>
          <input id="email" name="email" type="email" autoComplete="username" required />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
          />
        </div>
        <button type="submit">Continue</button>
      </form>
    </main>
  )
}
