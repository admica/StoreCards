import { NextRequest, NextResponse } from 'next/server'
import NextAuth from 'next-auth'
import { authConfig } from './auth.config'
import { checkRateLimit } from '@/app/lib/rate-limit'

const AUTH_PATHS = ['/api/auth/callback/credentials', '/login', '/register']

const { auth } = NextAuth(authConfig)

// auth() from NextAuth accepts NextAuthRequest which extends NextRequest.
// The cast is required because the overload resolution prefers the callback
// form over the direct-call form without explicit narrowing.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const authMiddleware = auth as (req: NextRequest) => Promise<any>

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl
  const isAuthPath = AUTH_PATHS.some(p => pathname.startsWith(p))

  if (isAuthPath && request.method === 'POST') {
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
      ?? request.headers.get('x-real-ip')
      ?? '127.0.0.1'

    const { allowed, minutesLeft } = checkRateLimit(ip)
    if (!allowed) {
      return new NextResponse(
        JSON.stringify({ error: `Too many attempts. Try again in ${minutesLeft} minutes.` }),
        { status: 429, headers: { 'Content-Type': 'application/json' } }
      )
    }
  }

  // Delegate auth routing to NextAuth (same behavior as old middleware.ts)
  return authMiddleware(request)
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|.*\\.png$).*)'],
}
