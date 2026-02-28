# Architecture Research

**Domain:** Loyalty card PWA — Next.js App Router production upgrade
**Researched:** 2026-02-28
**Confidence:** HIGH (official docs + verified sources for all four integration areas)

## Standard Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Browser / PWA Shell                          │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │  React Client │  │  Service     │  │   IndexedDB /      │    │
│  │  Components   │  │  Worker (SW) │  │   Cache API        │    │
│  └──────┬───────┘  └──────┬───────┘  └────────────────────┘    │
│         │                 │                                      │
│         │ Server Actions  │ Precache + Runtime Cache             │
└─────────┼─────────────────┼──────────────────────────────────────┘
          │                 │
┌─────────▼─────────────────▼──────────────────────────────────────┐
│                    Next.js Server (Node)                          │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ Middleware  │  │ Server       │  │  API Routes              │  │
│  │ (rate limit │  │ Components + │  │  (Stripe webhook,        │  │
│  │  + auth     │  │ Actions      │  │   checkout)              │  │
│  │  gate)      │  │ (feature     │  │                          │  │
│  └────────────┘  │  gate +      │  └──────────────────────────┘  │
│                  │  cookie read) │                                 │
│                  └──────┬───────┘                                 │
│                         │                                         │
│  ┌──────────────────────▼──────────────────────────────────────┐  │
│  │              lib/ (SubscriptionService, Prisma singleton)    │  │
│  └──────────────────────┬──────────────────────────────────────┘  │
└─────────────────────────┼──────────────────────────────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │   PostgreSQL (Docker Compose)   │
          └────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Communicates With |
|-----------|---------------|-------------------|
| Service Worker (`app/sw.ts` → `public/sw.js`) | Precache static assets + JS bundles; cache-first for `/uploads/*`; network-first with offline fallback for navigation | Cache API, Next.js build output |
| Middleware (`middleware.ts`) | Auth gate + subscription-selection redirect + rate limit check via `Next-Action` header detection | NextAuth `authorized` callback, in-memory rate store |
| Root Layout (`app/layout.tsx`) | Read `theme` cookie server-side; apply `dark` class to `<html>` before paint; no DB query for theme | `cookies()` from `next/headers`, `ThemeProvider` |
| Feature Gate Helper (`lib/feature-gate.ts`) | Check session + subscription tier; throw or return capability flags; memoized with React `cache()` | `auth()`, Prisma `subscription` table |
| Server Actions (`app/lib/actions.ts`) | Mutating business logic; call feature gate at entry point; return structured errors | Feature gate helper, Prisma, SubscriptionService |
| ThemeProvider (`app/providers/theme-provider.tsx`) | Client-side theme toggle; write `theme` cookie via Server Action on change | Cookie Server Action, React Context |
| SubscriptionService (`lib/stripe.ts`) | Stripe SDK ops; webhook state sync | Stripe API, Prisma |
| Prisma Singleton (`lib/prisma.ts`) | Single DB connection; hot-reload guard | PostgreSQL |

## Recommended Project Structure

```
app/
├── sw.ts                    # Serwist service worker source (compiled → public/sw.js)
├── layout.tsx               # Reads theme cookie, no DB query for theme
├── lib/
│   ├── actions.ts           # Server Actions — calls feature gate at top of each gated fn
│   ├── hooks/
│   │   └── useBarcodeScanner.ts  # Extracted shared hook (eliminates duplication)
│   ├── rate-limit.ts        # In-memory rate limiter (Map-based, single-instance safe)
│   └── cookie-actions.ts    # 'use server' — setThemeCookie, readThemeCookie
├── providers/
│   └── theme-provider.tsx   # Client toggle; calls cookie-actions.ts on change
lib/
├── feature-gate.ts          # requireFeature(userId, feature) — memoized with cache()
├── prisma.ts                # Prisma singleton (unchanged)
├── stripe.ts                # SubscriptionService (unchanged)
middleware.ts                # Auth + rate limit for auth routes
```

### Structure Rationale

- **`app/sw.ts`:** Serwist convention — service worker source lives in `app/` for App Router; build output goes to `public/sw.js`
- **`lib/feature-gate.ts`:** Lives in `lib/` not `app/lib/` because it is used by both API routes and Server Actions — shared server-only utility
- **`lib/rate-limit.ts`:** In-memory Map — acceptable for single Docker container deployment; no Redis dependency required
- **`app/lib/cookie-actions.ts`:** Server Actions are the only way to write cookies from the client-side toggle without a full API route

## Architectural Patterns

### Pattern 1: Serwist Offline Cache Strategy (Turbopack-aware)

**What:** Use `@serwist/turbopack` (not `@serwist/next`) since Next.js 16 defaults Turbopack for dev. Production build uses `withSerwist` from `@serwist/turbopack`; service worker source compiled from `app/sw.ts` via a route handler at `app/serwist/[path]/route.ts`.

**When to use:** Always — this is the path for Next.js 16 + Turbopack projects using Serwist.

**Trade-offs:** Turbopack path requires `esbuild` as dev dependency for SW compilation; slightly more setup than webpack path but dev experience is cleaner (no `--webpack` flag needed in dev).

**Example:**
```typescript
// next.config.mjs
import withSerwist from "@serwist/turbopack";

const nextConfig = {
  reactStrictMode: true,
  serverExternalPackages: ['@prisma/client'],
  output: 'standalone',
};

export default withSerwist(nextConfig);

// app/serwist/[path]/route.ts
import { createSerwistRoute } from "@serwist/turbopack/server";
export const { GET } = createSerwistRoute({
  swSrc: "app/sw.ts",
  additionalPrecacheEntries: [],
});

// app/sw.ts
import { defaultCache } from "@serwist/next/worker";
import { Serwist } from "serwist";

declare const self: ServiceWorkerGlobalScope;

const serwist = new Serwist({
  precacheEntries: self.__SW_MANIFEST,
  skipWaiting: true,
  clientsClaim: true,
  runtimeCaching: [
    // Cache-first: uploaded card images (core offline use case)
    {
      matcher: ({ url }) => url.pathname.startsWith("/uploads/"),
      handler: new CacheFirst({ cacheName: "card-images" }),
    },
    // Network-first: dashboard and card pages (show latest, fall back offline)
    {
      matcher: ({ request }) => request.destination === "document",
      handler: new NetworkFirst({ cacheName: "pages" }),
    },
    ...defaultCache,
  ],
  fallbacks: {
    entries: [{ url: "/~offline", matcher: ({ request }) => request.destination === "document" }],
  },
});

serwist.addEventListeners();
```

### Pattern 2: Cookie-Based Theme (No DB Query on Layout Render)

**What:** Root layout reads `theme` cookie via `cookies()` from `next/headers`. Theme toggle writes cookie via a `'use server'` action. Eliminates the `auth() + prisma.user.findUnique` call currently in `getInitialTheme()`.

**When to use:** Any preference that is per-client, not per-user-account. Theme is a browser preference, not user data.

**Trade-offs:** Dynamic rendering opted into for root layout (already the case since `cookies()` is a Dynamic API — but this was also true before because `auth()` was called). No regression. First load without cookie defaults to `light` without a DB hit.

**Example:**
```typescript
// app/layout.tsx (server component)
import { cookies } from 'next/headers';

export default async function RootLayout({ children }) {
  const cookieStore = await cookies();
  const theme = cookieStore.get('theme')?.value ?? 'light';

  return (
    <html lang="en" className={theme === 'dark' ? 'dark' : ''}>
      {/* no DB query, no auth() call for theme */}
      <body>
        <ThemeProvider initialTheme={theme as 'light' | 'dark'}>
          {children}
        </ThemeProvider>
      </body>
    </html>
  );
}

// app/lib/cookie-actions.ts
'use server';
import { cookies } from 'next/headers';

export async function setThemeCookie(theme: 'light' | 'dark') {
  const cookieStore = await cookies();
  cookieStore.set('theme', theme, {
    httpOnly: false,         // Client JS can read it for ThemeProvider hydration
    sameSite: 'lax',
    maxAge: 60 * 60 * 24 * 365,  // 1 year
    path: '/',
  });
}
```

### Pattern 3: In-Memory Rate Limiting for Server Actions

**What:** Module-level `Map` tracking IP + endpoint hit counts with TTL. Checked in Middleware for auth routes (using `Next-Action` header detection) and directly at the top of sensitive Server Actions. Returns structured error objects (not HTTP 429) since Server Actions can't return Response objects.

**When to use:** Self-hosted single-container deployment. No Redis/Upstash needed. Resets on process restart (acceptable for auth brute-force prevention on a single container).

**Trade-offs:** Not shared across multiple instances. For single Docker Compose deployment this is fine. If horizontal scaling is ever added, replace with Redis-backed limiter.

**Example:**
```typescript
// lib/rate-limit.ts
const store = new Map<string, { count: number; resetAt: number }>();

export function rateLimit(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const entry = store.get(key);

  if (!entry || now > entry.resetAt) {
    store.set(key, { count: 1, resetAt: now + windowMs });
    return true; // allowed
  }

  if (entry.count >= max) return false; // blocked

  entry.count++;
  return true;
}

// In a Server Action:
export async function register(prevState: unknown, formData: FormData) {
  const ip = (await headers()).get('x-forwarded-for')?.split(',')[0] ?? 'unknown';
  if (!rateLimit(`register:${ip}`, 5, 15 * 60 * 1000)) {
    return { error: 'Too many attempts. Try again in 15 minutes.' };
  }
  // ... rest of registration logic
}
```

### Pattern 4: Feature Gate Helper (Subscription Tier Enforcement)

**What:** A single `requireFeature(feature)` async function that reads the session and subscription from the DB, memoized with React `cache()` to avoid duplicate queries within the same render pass. Called at the top of every gated Server Action and used in Server Components to conditionally render premium UI.

**When to use:** Any Server Action or Server Component that requires a non-FREE subscription capability.

**Trade-offs:** Adds one DB query per gated action (mitigated by `cache()` memoization within a request). Feature flags must be defined in a central enum to avoid string typos.

**Example:**
```typescript
// lib/feature-gate.ts
import { cache } from 'react';
import { auth } from '@/auth';
import { prisma } from '@/lib/prisma';

export type Feature = 'unlimited_cards' | 'export_cards' | 'priority_support';

const TIER_FEATURES: Record<string, Feature[]> = {
  FREE:    [],
  MONTHLY: ['unlimited_cards', 'export_cards', 'priority_support'],
  YEARLY:  ['unlimited_cards', 'export_cards', 'priority_support'],
};

// cache() memoizes per request — multiple calls within one render won't re-query
export const getSubscriptionTier = cache(async (userId: string) => {
  const sub = await prisma.subscription.findUnique({ where: { userId } });
  return sub?.tier ?? 'FREE';
});

export async function requireFeature(feature: Feature): Promise<void> {
  const session = await auth();
  if (!session?.user?.id) throw new Error('Unauthenticated');

  const tier = await getSubscriptionTier(session.user.id);
  const allowed = TIER_FEATURES[tier] ?? [];
  if (!allowed.includes(feature)) {
    throw new Error('UpgradeRequired');
  }
}

// Usage in a Server Action:
export async function exportCards() {
  await requireFeature('export_cards');
  // ... export logic
}

// Usage in a Server Component:
const tier = await getSubscriptionTier(session.user.id);
const canExport = TIER_FEATURES[tier]?.includes('export_cards');
```

## Data Flow

### Request Flow: Page Load (After Cookie Migration)

```
Browser GET /dashboard
    ↓
middleware.ts
  - NextAuth authorized() → check session + subscriptionSelected
  - Rate limit check (non-auth route: skip)
    ↓
app/dashboard/page.tsx (Server Component)
  - auth() → session
  - getSubscriptionTier(userId) → tier (via feature-gate helper)
  - prisma.card.findMany → cards
  - Render: gate premium UI behind tier check
    ↓
app/layout.tsx
  - cookies().get('theme') → theme class on <html> (NO DB QUERY)
    ↓
HTML response → Service Worker intercepts on repeat visits
  - Precached JS/CSS served from Cache API
  - /uploads/* images served cache-first
```

### Request Flow: Auth Rate Limiting

```
POST /api/auth/callback/credentials  (login attempt)
    ↓
middleware.ts
  - Detects Next-Action or auth route pattern
  - rateLimit(`login:${ip}`, 10, 15min) → blocked? → 429 or set header flag
    ↓
auth.ts authorize() callback
  - bcrypt.compare() → session creation
```

### Request Flow: Gated Server Action

```
Client triggers Server Action (e.g., exportCards)
    ↓
Server Action entry point
  - await requireFeature('export_cards')
    - auth() → session (memoized)
    - getSubscriptionTier(userId) → DB query (memoized via cache())
    - tier check → throw 'UpgradeRequired' if FREE
  - If allowed: execute mutation
  - Return { success } or { error }
    ↓
Client component receives error object
  - Display upgrade prompt if error === 'UpgradeRequired'
```

### Service Worker Data Flow (Offline Card Access)

```
User opens /card/[id] while offline
    ↓
Service Worker fetch handler
  - Navigation request → NetworkFirst strategy
  - Network fails → serve cached /card/[id] from Cache API
  - Card image (url.pathname starts with /uploads/) → CacheFirst
    - Cached at first online visit, served offline thereafter
    ↓
User sees card + barcode without network
```

### State Management

```
Theme preference:
  Cookie ('theme') ←──── setThemeCookie() Server Action
       ↓ (read on every server render)
  <html class="dark"> (no hydration mismatch)
       ↓
  ThemeProvider (client) ← toggle button → setThemeCookie()

Subscription state:
  PostgreSQL (source of truth)
       ↓ Stripe webhook → syncSubscriptionFromStripe()
  JWT token (cached copy, refreshes on trigger: 'update')
       ↓
  Session callbacks → feature gate reads fresh from DB (not JWT)
```

## Integration Points

### External Services

| Service | Integration Pattern | Notes |
|---------|---------------------|-------|
| Stripe | Webhook POST → `app/api/webhooks/stripe/route.ts` → `SubscriptionService.syncSubscriptionFromStripe()` | Signature verified via `stripe.webhooks.constructEvent`; subscription state written to DB |
| Stripe Checkout | Server Action → `SubscriptionService.createCheckoutSession()` → redirect to Stripe-hosted page | Feature gate must NOT block checkout initiation |
| logo.dev / Clearbit | `searchLogos` Server Action → parallel `Promise.all` fetch | Rate-limit this action by user ID; debounce client-side |
| Serwist Build | `withSerwist` wraps `next.config.mjs`; compiles `app/sw.ts` → `public/sw.js` at build time | Requires `@serwist/turbopack` + `esbuild` dev dep for Next.js 16 Turbopack builds |

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| Service Worker ↔ Next.js pages | Cache API only; SW intercepts fetch events | SW never calls Server Actions directly; it caches their HTML responses |
| Feature Gate ↔ Server Actions | Direct function call (`await requireFeature(...)`) | Gate throws; action catches and returns `{ error: 'UpgradeRequired' }` to client |
| ThemeProvider ↔ Cookie | Server Action writes cookie; Server Component reads it | Do NOT store theme in DB anymore; migrate existing `darkMode` column to cookie on first login |
| Rate Limiter ↔ Middleware | Imported module-level Map | Reset on deploy — acceptable; brute-force window is short |
| JWT ↔ Subscription DB | JWT holds cached tier; feature gate reads DB directly (not JWT) | Avoids stale-JWT authorization bugs; DB query is memoized per request |

## Scaling Considerations

| Scale | Architecture Adjustments |
|-------|--------------------------|
| 0-1k users | Current monolith is fine; in-memory rate limiter sufficient; single PostgreSQL container |
| 1k-10k users | Replace in-memory rate limiter with Redis (add to Docker Compose); add nginx reverse proxy for rate limiting at infra level; consider PgBouncer for connection pooling |
| 10k+ users | Migrate local filesystem image storage to object storage (S3 / Cloudflare R2); horizontal scaling then becomes possible |

### Scaling Priorities

1. **First bottleneck:** Local filesystem images — prevents horizontal scaling entirely. Migrate to object storage before adding any second container.
2. **Second bottleneck:** In-memory rate limiter — not shared across instances. Replace with Redis-backed limiter when deploying more than one Node process.

## Anti-Patterns

### Anti-Pattern 1: DB Query for Theme in Root Layout

**What people do:** Call `auth()` + `prisma.user.findUnique` in `app/layout.tsx` to load `darkMode` preference (current state of StoreCard).

**Why it's wrong:** Adds a DB round-trip to every page render including public routes. Theme is a client preference, not server-authoritative data.

**Do this instead:** Store theme in a cookie. Read with `cookies()` in the server layout — zero DB cost, still no flash.

### Anti-Pattern 2: JWT-Based Feature Authorization

**What people do:** Read subscription tier from `session.user.subscription` (JWT) inside Server Actions to gate features.

**Why it's wrong:** JWT is a cached snapshot. After a Stripe webhook updates subscription state, the user's active session JWT may still reflect the old tier for minutes or hours. A downgraded user could continue accessing paid features.

**Do this instead:** Call `getSubscriptionTier(userId)` from the DB (memoized with `cache()`) inside the feature gate. JWT is fine for UI hints (show/hide upgrade buttons) but never for enforcement.

### Anti-Pattern 3: Service Worker Caching POST / Server Action Responses

**What people do:** Write a catch-all SW fetch handler that caches all same-origin responses, including Server Action POST requests.

**Why it's wrong:** Server Actions use POST. POSTs must never be served from cache — they mutate state. A cached mutation response could replay stale data or skip the actual mutation.

**Do this instead:** Only cache GET requests in the SW. The existing `if (request.method !== 'GET') return;` guard in the current `public/sw.js` is correct — preserve this in the Serwist migration.

### Anti-Pattern 4: Turbopack with `@serwist/next` (Webpack Plugin)

**What people do:** Install `@serwist/next` and use `withSerwistInit` from `@serwist/next` with Next.js 16 default builds (Turbopack).

**Why it's wrong:** `@serwist/next` uses a webpack plugin and cannot run under Turbopack. The build will fail silently or produce no service worker.

**Do this instead:** Use `@serwist/turbopack` for Next.js 16 projects. Install `esbuild` as a dev dependency. Follow the Turbopack quick guide at `serwist.pages.dev/docs/next/turbo`.

## Build Order Implications

The four integration areas have these dependencies:

```
1. Cookie-based theme           — Independent; no deps on other areas
        ↓
2. Rate limiting                — Independent; can ship alongside (1) or separately
        ↓
3. Feature gate infrastructure  — Depends on: subscription DB state is accurate (Stripe webhook working)
        ↓
4. Offline PWA (Serwist)        — Depends on: stable page HTML (theme/auth working correctly)
                                — Build last: SW precaches the final compiled output
```

**Recommended phase order:**
1. Cookie theme + rate limiting (parallel — both are independent plumbing changes)
2. Feature gate (requires knowing which features to gate; implement infrastructure first, gates TBD)
3. Serwist offline PWA (implement last so precache captures stable, final app shell)

## Sources

- Next.js official PWA guide (verified 2026-02-27): https://nextjs.org/docs/app/guides/progressive-web-apps
- Serwist Turbopack guide: https://serwist.pages.dev/docs/next/turbo
- Serwist webpack guide: https://serwist.pages.dev/docs/next/getting-started
- Next.js cookies() API reference: https://nextjs.org/docs/app/api-reference/functions/cookies
- Next.js rate limiting Server Actions discussion: https://github.com/vercel/next.js/discussions/62557
- Rate-limiting Server Actions pattern: https://nextjsweekly.com/blog/rate-limiting-server-actions
- LogRocket Next.js 16 PWA offline support (Jan 2026): https://blog.logrocket.com/nextjs-16-pwa-offline-support/
- Next.js 16 Turbopack default announcement: https://akoskm.com/nextjs-16-turbopack-stable/

---
*Architecture research for: StoreCard — loyalty card PWA production upgrade*
*Researched: 2026-02-28*
