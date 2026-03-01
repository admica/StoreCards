# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

StoreCard is a loyalty/store card management PWA built with Next.js 16 (App Router), React 19, TypeScript, and Tailwind CSS 4. Users can scan, store, and manage loyalty cards with barcode support. Self-hosted with local PostgreSQL.

## Commands

- `npm run dev` — Start development server (port 3000)
- `npm run build` — Production build
- `npm run lint` — ESLint
- `npx prisma migrate dev` — Run database migrations
- `npx prisma generate` — Regenerate Prisma client after schema changes
- `npx prisma studio` — Browse database in GUI
- `docker-compose up -d` — Start local PostgreSQL

## Architecture

**App Router structure** — All pages under `app/`, server components by default. Client components marked with `"use client"`.

**Server Actions** — Core business logic lives in `app/lib/actions.ts` (card CRUD, user registration, settings updates). These are called directly from forms and client components via `useFormState`.

**Authentication** — NextAuth.js v5 (beta) with credentials provider only. Config split across:
- `auth.ts` — NextAuth initialization with credentials provider, bcrypt password verification
- `auth.config.ts` — JWT/session callbacks that enrich tokens with subscription data
- `middleware.ts` — Route protection; public routes are `/`, `/login`, `/register`

**Auth flow**: After registration, users get a FREE subscription auto-created and are redirected to `/subscribe` for plan selection. The `subscriptionSelected` flag on User controls this redirect.

**Payments** — `lib/stripe.ts` contains a `SubscriptionService` class with static methods for Stripe operations. Webhook handler at `app/api/webhooks/stripe/route.ts` syncs subscription state. Two plans: monthly ($4) and yearly ($40), currently shown as "Coming Soon" in UI.

**Database** — PostgreSQL via Prisma ORM. Schema in `prisma/schema.prisma`. Four models: User, Subscription, Card, BrandLogo. Prisma client singleton in `lib/prisma.ts`. Single `DATABASE_URL` connection string for local PostgreSQL.

**Image/Barcode Pipeline**:
- Scanning: ZXing library with multi-rotation fallback and image preprocessing (`app/lib/image-utils.ts`)
- Generation: bwip-js renders barcodes for display (`app/components/Barcode.tsx`)
- Color extraction: colorthief pulls dominant colors from card images, generates light/dark variants (`app/lib/color-utils.ts`)
- Brand logos cached in BrandLogo table to avoid repeated lookups
- Card images stored on local filesystem in `public/uploads/`

**Styling** — Pure Tailwind CSS 4 with custom theme variables in `app/globals.css`. Light/dark mode via `.dark` class on `<html>`. No component library. Theme context in `app/providers/theme-provider.tsx`.

**Path alias** — `@/*` maps to project root (tsconfig.json).

## Key Environment Variables

`DATABASE_URL`, `AUTH_SECRET`, `NEXTAUTH_URL`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`, `LOGO_DEV_SECRET`
