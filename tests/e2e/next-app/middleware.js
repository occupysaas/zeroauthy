import { auth0 } from './lib/auth0';

export async function middleware(request) {
  return await auth0.middleware(request);
}

export const config = {
  runtime: 'nodejs',
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
