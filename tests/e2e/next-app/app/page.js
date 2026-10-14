import { auth0 } from '../lib/auth0';

export const dynamic = 'force-dynamic';

export default async function Home() {
  const session = await auth0.getSession();
  if (!session) {
    return <main><a id="login" href="/auth/login">Log in</a></main>;
  }
  return (
    <main>
      <p id="email">{session.user.email}</p>
      <a id="logout" href="/auth/logout">Log out</a>
    </main>
  );
}
