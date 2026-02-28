# External Integrations

**Analysis Date:** 2026-02-28

## APIs & External Services

**Payments:**
- Stripe - Subscription billing (monthly at $4, yearly at $40)
  - SDK/Client: `stripe` 20.0.0 (server), `@stripe/stripe-js` 8.5.3 (client)
  - Auth: `STRIPE_SECRET_KEY` (server), `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` (client)
  - Webhook secret: `STRIPE_WEBHOOK_SECRET`
  - Price IDs: `STRIPE_MONTHLY_PRICE_ID`, `STRIPE_YEARLY_PRICE_ID`
  - Service class: `lib/stripe.ts` (`SubscriptionService`)
  - Webhook handler: `app/api/webhooks/stripe/route.ts`
  - API version pinned: `2025-11-17.clover`

**Brand Logo Search (optional, best-effort):**
- Clearbit Autocomplete API - Free company logo search; no auth required
  - Endpoint: `https://autocomplete.clearbit.com/v1/companies/suggest?query=...`
  - Called in: `app/lib/actions.ts` (server action `searchLogos`)
- Logo.dev API - Paid logo search; only active when secret is configured
  - Endpoint: `https://api.logo.dev/search?q=...`
  - Auth: `LOGO_DEV_SECRET` env var (Bearer token)
  - Called in: `app/lib/actions.ts` (server action `searchLogos`)
- Google Favicon Service - Free fallback favicon fetcher; no auth required
  - Endpoint: `https://www.google.com/s2/favicons?domain=...&sz=128`
  - Used as default fallback when no cached logo or API results available

## Data Storage

**Databases:**
- PostgreSQL 15 (self-hosted via Docker)
  - Connection: `DATABASE_URL` env var
  - Client: Prisma ORM 5.22.x; singleton at `lib/prisma.ts`
  - Schema: `prisma/schema.prisma`
  - Models: `User`, `Subscription`, `Card`, `BrandLogo`
  - Migrations: `prisma/migrations/`

**File Storage:**
- Local filesystem only
  - Card images stored at `public/uploads/` on the server
  - Docker volume mount: `./public/uploads:/app/public/uploads`
  - No external object storage (no S3, GCS, etc.)

**Caching:**
- Database-level caching only
  - Brand logos cached in `BrandLogo` table to avoid repeated API lookups

## Authentication & Identity

**Auth Provider:**
- NextAuth.js v5 (beta) with credentials-only provider
  - Implementation: JWT strategy; session data populated from DB at sign-in and refreshed on `trigger === 'update'`
  - Config: `auth.ts` (provider + authorize), `auth.config.ts` (JWT/session callbacks)
  - Middleware: `middleware.ts` — protects all routes except `/`, `/login`, `/register`
  - Passwords: bcrypt hashed via `bcryptjs`
  - Custom session fields: `id`, `onboardingComplete`, `subscriptionSelected`, `subscription` (tier, status, currentPeriodEnd, isActive, isFree)

## Monitoring & Observability

**Error Tracking:**
- None detected - no Sentry, Datadog, or similar integration present

**Logs:**
- `console.log` / `console.error` / `console.warn` throughout server-side code
- No structured logging framework

## CI/CD & Deployment

**Hosting:**
- Self-hosted via Docker Compose (`docker-compose.yml`)
- Two services: `storecards-app` (Next.js standalone) + `db` (PostgreSQL 15)
- App exposed on port 3000

**CI Pipeline:**
- None detected - no GitHub Actions, CircleCI, or similar config present

## Environment Configuration

**Required env vars:**
- `DATABASE_URL` - PostgreSQL connection string
- `AUTH_SECRET` - NextAuth signing secret (generate with `npx auth secret`)
- `NEXTAUTH_URL` - Full app URL (e.g. `http://localhost:3000`)
- `STRIPE_SECRET_KEY` - Stripe server-side secret key (`sk_...`)
- `STRIPE_WEBHOOK_SECRET` - Stripe webhook signing secret (`whsec_...`)
- `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY` - Stripe public key (`pk_...`)
- `STRIPE_MONTHLY_PRICE_ID` - Stripe Price ID for monthly plan
- `STRIPE_YEARLY_PRICE_ID` - Stripe Price ID for yearly plan

**Optional env vars:**
- `LOGO_DEV_SECRET` - Bearer token for logo.dev API (logo search enhancement)

**Secrets location:**
- `.env` / `.env.local` files (not committed); template at `env.example`

## Webhooks & Callbacks

**Incoming (from Stripe):**
- `POST /api/webhooks/stripe` — Receives Stripe webhook events
  - Handler: `app/api/webhooks/stripe/route.ts`
  - Verified via `stripe-signature` header + `STRIPE_WEBHOOK_SECRET`
  - Handled events:
    - `customer.subscription.created`
    - `customer.subscription.updated`
    - `customer.subscription.deleted`
    - `invoice.payment_succeeded`
    - `invoice.payment_failed`

**Outgoing:**
- Stripe Checkout Sessions - created server-side via `SubscriptionService.createCheckoutSession()` in `lib/stripe.ts`
- Logo/favicon API calls - `app/lib/actions.ts` makes outbound HTTP requests to Clearbit, Logo.dev, and Google Favicon

---

*Integration audit: 2026-02-28*
