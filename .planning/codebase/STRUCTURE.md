# Codebase Structure

**Analysis Date:** 2026-02-28

## Directory Layout

```
storecard/
├── app/                        # Next.js App Router — all pages and API routes
│   ├── add/                    # Add card page
│   │   ├── page.tsx            # Server component: loads nerdMode pref, renders form
│   │   └── add-card-form.tsx   # Client component: form UI, camera/barcode scanning
│   ├── api/                    # HTTP API routes (external-facing only)
│   │   ├── auth/               # Auth flows
│   │   │   ├── [...nextauth]/  # NextAuth built-in handler
│   │   │   ├── send-verification-code/
│   │   │   └── verify-email/
│   │   ├── create-checkout-session/  # Stripe checkout initiation
│   │   ├── subscription/       # Subscription management endpoints
│   │   │   ├── cancel/
│   │   │   ├── status/
│   │   │   └── update/
│   │   ├── test-email/
│   │   └── webhooks/
│   │       └── stripe/         # Stripe webhook receiver
│   ├── card/
│   │   └── [id]/               # Dynamic card detail route
│   │       ├── page.tsx        # Server component: loads card data
│   │       ├── card-view.tsx   # Client component: display barcode, mark used
│   │       └── edit/           # Edit card route
│   │           └── page.tsx
│   ├── components/             # Shared UI components (used across routes)
│   │   ├── BottomNav.tsx       # Client: persistent bottom navigation
│   │   └── Barcode.tsx         # Client: bwip-js barcode canvas renderer
│   ├── dashboard/
│   │   └── page.tsx            # Server component: card list
│   ├── lib/                    # App-level utilities and server actions
│   │   ├── actions.ts          # ALL server actions (mutations)
│   │   ├── color-utils.ts      # Client: color extraction, HSL/RGB/hex helpers
│   │   └── image-utils.ts      # Client: barcode image preprocessing, rotation
│   ├── login/
│   │   └── page.tsx
│   ├── providers/
│   │   └── theme-provider.tsx  # React Context for light/dark theme
│   ├── register/
│   │   └── page.tsx
│   ├── settings/
│   │   ├── page.tsx
│   │   ├── dark-mode-toggle.tsx
│   │   └── nerd-mode-toggle.tsx
│   ├── subscribe/
│   │   └── page.tsx            # Plan selection (client component)
│   ├── verify-email/
│   │   └── page.tsx
│   ├── globals.css             # Tailwind CSS 4 base + custom theme variables
│   ├── layout.tsx              # Root layout: fonts, PWA meta, ThemeProvider, BottomNav
│   ├── manifest.ts             # PWA manifest generator
│   ├── page.tsx                # Landing page (public)
│   ├── robots.ts
│   └── sitemap.ts
├── components/                 # Root-level components directory (currently: logo-picker.tsx)
│   └── logo-picker.tsx         # Client: brand logo search and selection UI
├── lib/                        # Root-level shared libraries
│   ├── prisma.ts               # Prisma client singleton
│   └── stripe.ts               # SubscriptionService class + stripe() lazy initializer
├── prisma/
│   ├── schema.prisma           # Database schema: User, Subscription, Card, BrandLogo
│   └── migrations/             # Prisma migration history
├── public/
│   ├── uploads/                # User-uploaded card images (written at runtime)
│   ├── sw.js                   # Service worker for PWA offline support
│   ├── icon-192.png            # PWA app icon
│   └── icon-512.png            # PWA app icon
├── types/
│   ├── next-auth.d.ts          # Module augmentation: adds subscription fields to session
│   └── colorthief.d.ts         # Type declarations for colorthief library
├── auth.ts                     # NextAuth initialization: credentials provider, exports handlers
├── auth.config.ts              # NextAuth callbacks: JWT enrichment, route authorization
├── middleware.ts               # Edge middleware: delegates to NextAuth authorized callback
├── tsconfig.json               # TS config: strict mode, @/* path alias
├── next.config.mjs             # Next.js config
├── docker-compose.yml          # Local PostgreSQL container
├── Dockerfile                  # Production container definition
└── CLAUDE.md                   # Project guidance for AI assistants
```

## Directory Purposes

**`app/` (pages and routes):**
- Purpose: All Next.js App Router pages and API handlers
- Contains: Server components (`page.tsx`), co-located client sub-components, API route handlers (`route.ts`)
- Key files: `app/layout.tsx` (root layout), `app/page.tsx` (landing)
- Pattern: Each route directory contains a `page.tsx` server component that fetches data and passes it to client sub-components

**`app/lib/`:**
- Purpose: Server-side business logic and client-side utilities for the app layer
- Contains: `actions.ts` (all server mutations), `color-utils.ts` (client color processing), `image-utils.ts` (client image/barcode processing)
- Note: `color-utils.ts` and `image-utils.ts` are browser-only despite living in `app/lib/`

**`app/components/`:**
- Purpose: Shared UI components reused across multiple routes
- Contains: `BottomNav.tsx`, `Barcode.tsx`
- All components here are client components (`'use client'`)

**`app/providers/`:**
- Purpose: React Context providers wrapping the app
- Contains: `theme-provider.tsx` — ThemeContext, ThemeProvider, useTheme hook

**`lib/` (root):**
- Purpose: Infrastructure singletons used by both API routes and server actions
- Contains: `prisma.ts` (DB client singleton), `stripe.ts` (SubscriptionService + stripe initializer)

**`components/` (root):**
- Purpose: Components too large or reusable to live in a single route directory
- Contains: `logo-picker.tsx` — brand logo search UI used in add/edit card forms

**`types/`:**
- Purpose: TypeScript module augmentation declarations
- Contains: `next-auth.d.ts` (extends Session/JWT types), `colorthief.d.ts`

**`prisma/`:**
- Purpose: Database schema definition and migration history
- Contains: `schema.prisma` (4 models: User, Subscription, Card, BrandLogo), `migrations/` subdirectory
- Generated: Prisma client in `node_modules/@prisma/client` after `npx prisma generate`

**`public/uploads/`:**
- Purpose: Runtime storage for user-uploaded card images
- Contains: UUID-named image files written by `createCard`/`updateCard` server actions
- Generated: Yes (at runtime), not in git (only directory stub committed)

## Key File Locations

**Entry Points:**
- `app/layout.tsx`: Root layout — theme init, PWA setup, persistent nav
- `app/page.tsx`: Public landing page
- `middleware.ts`: Route protection via NextAuth
- `auth.ts`: NextAuth exports (`handlers`, `auth`, `signIn`, `signOut`)
- `auth.config.ts`: JWT/session callbacks and `authorized` callback

**Configuration:**
- `tsconfig.json`: TypeScript config (`@/*` alias maps to project root)
- `next.config.mjs`: Next.js config
- `prisma/schema.prisma`: Database schema
- `docker-compose.yml`: Local PostgreSQL setup
- `app/globals.css`: Tailwind v4 theme variables (CSS custom properties)

**Core Logic:**
- `app/lib/actions.ts`: All server actions (card CRUD, auth, settings, plan selection, logo search)
- `lib/stripe.ts`: All Stripe operations via `SubscriptionService`
- `lib/prisma.ts`: Prisma client (import as `import { prisma } from '@/lib/prisma'`)
- `app/lib/color-utils.ts`: Color extraction and light/dark color generation
- `app/lib/image-utils.ts`: Barcode scanning image preprocessing

**API Routes:**
- `app/api/webhooks/stripe/route.ts`: Stripe webhook handler
- `app/api/create-checkout-session/route.ts`: Creates Stripe checkout session
- `app/api/auth/[...nextauth]/route.ts`: NextAuth HTTP handler
- `app/api/subscription/cancel/route.ts`: Cancel subscription
- `app/api/subscription/status/route.ts`: Get subscription status
- `app/api/subscription/update/route.ts`: Update subscription plan

**Shared UI:**
- `app/components/BottomNav.tsx`: Persistent bottom nav bar
- `app/components/Barcode.tsx`: Barcode canvas renderer
- `components/logo-picker.tsx`: Brand logo search/select widget

## Naming Conventions

**Files:**
- Pages: `page.tsx` (required by Next.js App Router)
- API handlers: `route.ts` (required by Next.js App Router)
- Client sub-components: `kebab-case.tsx` (e.g., `add-card-form.tsx`, `card-view.tsx`, `dark-mode-toggle.tsx`)
- Shared components: `PascalCase.tsx` (e.g., `BottomNav.tsx`, `Barcode.tsx`)
- Utility modules: `kebab-case.ts` (e.g., `color-utils.ts`, `image-utils.ts`)
- Library files: `kebab-case.ts` (e.g., `prisma.ts`, `stripe.ts`)

**Directories:**
- Route directories: `kebab-case` matching the URL path (e.g., `add/`, `verify-email/`)
- Dynamic segments: `[param]` (e.g., `[id]/`)

**Components:**
- Client components: Always have `'use client'` as first line
- Server components: No directive; async function components that call `auth()` and `prisma.*` directly

## Where to Add New Code

**New page/route:**
- Create `app/{route-name}/page.tsx` as a server component
- Co-locate client sub-components as `app/{route-name}/{component-name}.tsx`

**New server mutation:**
- Add to `app/lib/actions.ts` with `'use server'` file-level directive already in place
- Follow pattern: validate session with `auth()`, validate inputs with `z.object()`, perform Prisma operation, call `revalidatePath`, call `redirect`

**New API endpoint (external-facing):**
- Create `app/api/{endpoint-name}/route.ts`
- Use `auth()` for session validation; return `NextResponse.json()`

**New Stripe operation:**
- Add static method to `SubscriptionService` in `lib/stripe.ts`
- Use `stripe()` lazy initializer; update Prisma subscription record after Stripe call

**New shared UI component:**
- If used in 2+ routes: `app/components/ComponentName.tsx` (client) or `app/components/ComponentName.tsx` (server, no directive)
- Large/complex widget: `components/component-name.tsx` at root

**New utility function:**
- Browser-only (canvas, DOM): `app/lib/color-utils.ts` or `app/lib/image-utils.ts`
- Server-only or isomorphic: `lib/` at root

**New database model:**
- Add to `prisma/schema.prisma`
- Run `npx prisma migrate dev` then `npx prisma generate`

**New type declaration / module augmentation:**
- Add to `types/` directory

## Special Directories

**`.planning/`:**
- Purpose: GSD (Get Shit Done) planning artifacts — codebase maps, phases, epics
- Generated: No
- Committed: Yes

**`.claude/`:**
- Purpose: Claude Code agent configurations, custom slash commands, GSD workflow scripts
- Generated: No
- Committed: Yes

**`public/uploads/`:**
- Purpose: Runtime user-uploaded card images served as static files
- Generated: Yes (at runtime by server actions)
- Committed: Only the directory stub; individual files are gitignored

**`.next/`:**
- Purpose: Next.js build output and cache
- Generated: Yes
- Committed: No

**`prisma/migrations/`:**
- Purpose: Prisma migration SQL history
- Generated: Yes (via `npx prisma migrate dev`)
- Committed: Yes (migration files are source-controlled)

---

*Structure analysis: 2026-02-28*
