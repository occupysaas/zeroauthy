import { auth0 } from '../../../lib/auth0';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const { token } = await auth0.getAccessToken();
    return Response.json({ token });
  } catch (err) {
    return Response.json({ error: String(err.code || err.message) }, { status: 401 });
  }
}
