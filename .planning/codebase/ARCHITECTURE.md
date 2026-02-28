# Architecture

**Analysis Date:** 2026-02-28

## Pattern Overview

**Overall:** Next.js App Router with Server Components + Server Actions

**Key Characteristics:**
- Server Components by default; client components opted-in with `"use client"` at the top of the file
- Core CRUD business logic consolidated in a single Server Actions file rather than distributed across API routes
- JWT-based session with subscription data embedded in the token to avoid per-request DB queries
- Thin API routes for external-facing endpoints (Stripe webhooks, Stripe checkout initiation); everything else uses Server Actions

## Layers

**Routing / Pages Layer:**
- Purpose: Render UI, authenticate session, fetch data for display
- Location: `app/` (each subdirectory = a route)
- Contains: `page.tsx` (server component), co-located client sub-components (e.g., `add-card-form.tsx`, `card-view.tsx`)
- Depends on: `auth`, `lib/prisma`, `app/lib/actions`
- Used by: End users via browser

**Server Actions Layer:**
- Purpose: All mutating business logic (create/update/delete card, register, authenticate, select plan, update settings)
- Location: `app/lib/actions.ts`
- Contains: `'use server'` functions called directly from forms and client components via `useFormState`
- Depends on: `auth`, `lib/prisma`, `lib/stripe` (indirectly for plan selection)
- Used by: Page components, client form components

**API Routes Layer:**
- Purpose: External-facing HTTP endpoints only (Stripe webhooks, checkout session creation, email verification flows)
- Location: `app/api/`
- Contains: Route handlers (`route.ts`) under `/webhooks/stripe`, `/create-checkout-session`, `/subscription/*`, `/auth/*`
- Depends on: `auth`, `lib/prisma`, `lib/stripe`
- Used by: Stripe (webhooks), browser fetch calls for payment flows

**Service Layer:**
- Purpose: Encapsulate Stripe SDK operations
- Location: `lib/stripe.ts`
- Contains: `SubscriptionService` static class with methods for customer creation, checkout sessions, cancellation, plan updates, webhook sync
- Depends on: Stripe SDK, `lib/prisma`
- Used by: `app/api/webhooks/stripe/route.ts`, `app/api/create-checkout-session/route.ts`, `app/api/subscription/` routes

**Data Access Layer:**
- Purpose: Prisma client singleton for all database operations
- Location: `lib/prisma.ts`
- Contains: Singleton `PrismaClient` instance (guarded against hot-reload recreation in dev)
- Depends on: `DATABASE_URL` env var, `prisma/schema.prisma`
- Used by: All server-side code (actions, API routes, layout, pages)

**Authentication Layer:**
- Purpose: NextAuth.js v5 credentials provider; session/JWT enrichment with subscription state
- Location: `auth.ts` (main config + exports), `auth.config.ts` (callbacks + route authorization)
- Contains: `handlers`, `auth`, `signIn`, `signOut` exports; JWT callback enriches token with subscription data; `authorized` callback enforces subscription-selection redirect
- Depends on: `lib/prisma`, `bcryptjs`, `zod`
- Used by: `middleware.ts` (route protection), all pages that call `auth()`, `app/layout.tsx`

**Client Utilities Layer:**
- Purpose: Browser-side image processing and color extraction
- Location: `app/lib/image-utils.ts`, `app/lib/color-utils.ts`
- Contains: Barcode image preprocessing (EXIF handling, contrast enhancement, rotation), dominant color extraction via colorthief, light/dark color generation
- Depends on: Browser Canvas API, colorthief (dynamically imported)
- Used by: Add/edit card client form components

**UI Components Layer:**
- Purpose: Shared presentational components
- Location: `app/components/`
- Contains: `BottomNav.tsx` (client, persistent nav), `Barcode.tsx` (client, bwip-js canvas renderer)
- Depends on: bwip-js, Next.js navigation
- Used by: `app/layout.tsx` (BottomNav), card view pages (Barcode)

**Theme Layer:**
- Purpose: Light/dark mode state management
- Location: `app/providers/theme-provider.tsx`
- Contains: React Context (`ThemeContext`), `ThemeProvider` (client component), `useTheme` hook
- Depends on: React Context
- Used by: `app/layout.tsx` wraps entire app; `app/settings/` toggles consume `useTheme`

## Data Flow

**Card Creation:**
1. User navigates to `/add`; server component fetches `nerdMode` preference from DB
2. `AddCardForm` (client) renders; user fills fields, optionally scans barcode via ZXing/camera
3. On image select, `extractColorsFromImage` (client) runs colorthief against logo image
4. Form submitted → `createCard` Server Action (`app/lib/actions.ts`)
5. Server action validates session, writes file to `public/uploads/`, inserts `Card` row and upserts `BrandLogo` cache via Prisma
6. `revalidatePath('/dashboard')` + `redirect('/dashboard')` sends user back

**Authentication + Subscription Gate:**
1. User submits login form → `authenticate` Server Action calls NextAuth `signIn`
2. NextAuth `authorize` callback verifies bcrypt password via Prisma
3. JWT callback attaches `id`, `onboardingComplete`, `subscriptionSelected`, and `subscription` object to token
4. On every request, `middleware.ts` runs NextAuth `authorized` callback
5. If `subscriptionSelected === false`, middleware redirects to `/subscribe`
6. After plan selection, `selectPlan` Server Action updates DB; `redirect('/dashboard')`

**Stripe Webhook Sync:**
1. Stripe sends POST to `/api/webhooks/stripe`
2. Route handler verifies webhook signature with `stripe().webhooks.constructEvent`
3. Event dispatched to `SubscriptionService.syncSubscriptionFromStripe` or inline handlers
4. `prisma.subscription.update` writes new status/tier/period to DB

**Theme Initialization:**
1. `app/layout.tsx` (server) calls `auth()` + `prisma.user.findUnique` to load `darkMode` preference
2. `initialTheme` passed as prop to `ThemeProvider`; `dark` class applied to `<html>` server-side (no flash)
3. Client-side `ThemeProvider` manages subsequent toggle; changes persist via `updateDarkMode` Server Action

## Key Abstractions

**Server Actions (`app/lib/actions.ts`):**
- Purpose: Single file containing all `'use server'` mutations; acts as the application's command layer
- Pattern: Functions accept `(prevState, formData)` for `useFormState` compatibility or simple args for direct calls
- Examples: `createCard`, `updateCard`, `deleteCard`, `register`, `authenticate`, `selectPlan`, `updateNerdMode`, `searchLogos`

**SubscriptionService (`lib/stripe.ts`):**
- Purpose: Static class wrapping all Stripe SDK calls; decoupled from HTTP layer
- Pattern: Static methods receive `userId` + parameters; handle both Stripe API calls and Prisma updates
- Examples: `createOrGetCustomer`, `createCheckoutSession`, `cancelSubscription`, `syncSubscriptionFromStripe`

**Prisma Singleton (`lib/prisma.ts`):**
- Purpose: Single shared `PrismaClient` instance; prevents connection pool exhaustion during Next.js hot reload
- Pattern: `globalThis` guard; `const prisma = globalForPrisma.prisma || new PrismaClient()`

**NextAuth Session Extension (`types/next-auth.d.ts`):**
- Purpose: Augments `next-auth` types so `session.user` carries `onboardingComplete`, `subscriptionSelected`, and `subscription` object
- Pattern: `declare module 'next-auth'` augmentation

## Entry Points

**Root Layout (`app/layout.tsx`):**
- Location: `app/layout.tsx`
- Triggers: Every page render
- Responsibilities: Inter font, PWA metadata/viewport, service worker registration, theme initialization from DB, wraps app in `ThemeProvider`, renders persistent `BottomNav`

**Landing Page (`app/page.tsx`):**
- Location: `app/page.tsx`
- Triggers: `GET /`
- Responsibilities: Public marketing/landing page; redirected away if authenticated

**Middleware (`middleware.ts`):**
- Location: `middleware.ts`
- Triggers: Every request matching the matcher (all paths except static assets)
- Responsibilities: Delegates entirely to NextAuth `authorized` callback; enforces login redirect and subscription-selection gate

**NextAuth Handler (`app/api/auth/[...nextauth]/route.ts`):**
- Location: `app/api/auth/[...nextauth]/`
- Triggers: All `/api/auth/*` requests (sign-in, sign-out, session)
- Responsibilities: NextAuth built-in handler via `export { handlers as GET, handlers as POST }`

**Stripe Webhook (`app/api/webhooks/stripe/route.ts`):**
- Location: `app/api/webhooks/stripe/route.ts`
- Triggers: POST from Stripe events
- Responsibilities: Signature verification, event routing, subscription state sync to DB

## Error Handling

**Strategy:** Fail-safe with graceful degradation for non-critical operations; hard errors for security-critical paths.

**Patterns:**
- Server Actions return error strings (`'Not authenticated'`, `'User not found'`) or `{ error: string }` objects; calling components display these via `useFormState`
- Image upload and logo caching failures are silently swallowed with `// best-effort` comments; card creation continues
- Auth errors bubble up through `AuthError` instance checks in `authenticate` action
- Webhook handler: returns 400 on invalid signature, 503 if Stripe env vars missing, 500 for unexpected errors
- API routes use `try/catch` with `NextResponse.json({ error }, { status })` patterns

## Cross-Cutting Concerns

**Logging:** `console.error` / `console.warn` / `console.log` used directly; no structured logging library. Webhook events logged with `console.log('Received webhook event:', event.type)`.

**Validation:** `zod` used at auth boundaries (`register` action, `authenticate` action). No shared validation schemas; form field validation is ad-hoc within each action.

**Authentication:** Every server component and action calls `auth()` directly to get the session. No middleware-level auth injection into page props; each page is self-authenticating.

---

*Architecture analysis: 2026-02-28*
