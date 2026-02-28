# Technology Stack

**Analysis Date:** 2026-02-28

## Languages

**Primary:**
- TypeScript 5.9.x - All application code (`app/`, `lib/`, `auth.ts`, `middleware.ts`)

**Secondary:**
- CSS (Tailwind utility classes) - All styling in `app/globals.css` and component files

## Runtime

**Environment:**
- Node.js 18 (Docker base: `node:18-alpine`; local dev: v22.x detected)

**Package Manager:**
- npm (primary; Dockerfile also supports yarn/pnpm via detection logic)
- Lockfile: `package-lock.json` present (lockfileVersion 3)

## Frameworks

**Core:**
- Next.js 16.0.8 - Full-stack React framework (App Router); config at `next.config.mjs`
- React 19.2.1 - UI rendering
- React DOM 19.2.1 - DOM reconciler

**Authentication:**
- next-auth 5.0.0-beta.30 - Session management, JWT strategy; config split across `auth.ts` and `auth.config.ts`

**Build/Dev:**
- TypeScript compiler (via Next.js build pipeline)
- PostCSS with `@tailwindcss/postcss` 4.x - CSS processing; config at `postcss.config.mjs`
- Tailwind CSS 4.x - Utility-first styling
- ESLint 9.x with `eslint-config-next` 16.0.8 - Linting; config at `eslint.config.mjs`

## Key Dependencies

**Critical:**
- `@prisma/client` 5.22.x - Database ORM client; singleton at `lib/prisma.ts`
- `prisma` 5.22.x - ORM CLI + migration tooling; schema at `prisma/schema.prisma`
- `stripe` 20.0.0 - Server-side Stripe SDK; wrapper/service at `lib/stripe.ts` (API version `2025-11-17.clover`)
- `@stripe/stripe-js` 8.5.3 - Client-side Stripe.js loader
- `next-auth` 5.0.0-beta.30 - Authentication (beta, not stable)
- `bcryptjs` 3.0.3 - Password hashing for credentials auth; used in `auth.ts`
- `zod` 4.1.13 - Schema validation; used for credential parsing in `auth.ts`

**Barcode/Scanning:**
- `@zxing/browser` 0.1.5 - Barcode scanning from camera/files; used in card scanning flow
- `react-zxing` 1.1.3 - React wrapper for ZXing barcode scanning
- `bwip-js` 4.8.0 - Barcode image generation for display; used in `app/components/Barcode.tsx`

**Image/Color:**
- `colorthief` 2.6.0 - Dominant color extraction from images; used in `app/lib/color-utils.ts`

## Configuration

**Environment:**
- All configuration via environment variables; template at `env.example`
- Required: `DATABASE_URL`, `AUTH_SECRET`, `NEXTAUTH_URL`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`, `STRIPE_MONTHLY_PRICE_ID`, `STRIPE_YEARLY_PRICE_ID`
- Optional: `LOGO_DEV_SECRET`

**Build:**
- `next.config.mjs` - Next.js config; `output: 'standalone'` for Docker, `serverExternalPackages: ['@prisma/client']`
- `tsconfig.json` - TypeScript strict mode, `ES2017` target, `@/*` path alias mapping to project root
- `postcss.config.mjs` - PostCSS with Tailwind 4

## Platform Requirements

**Development:**
- Node.js 18+ (Docker uses 18-alpine)
- PostgreSQL 15 (Docker: `postgres:15-alpine`)
- `docker-compose up -d` starts local Postgres on port 5432

**Production:**
- Docker / Docker Compose self-hosted deployment
- Standalone Next.js output (`node server.js`)
- Persistent volume for `public/uploads/` (card images stored on local filesystem)
- PostgreSQL 15 database with `DATABASE_URL` connection string

---

*Stack analysis: 2026-02-28*
