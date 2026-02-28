# StoreCard

## What This Is

StoreCard is a loyalty/store card management PWA where users scan, store, and manage their loyalty cards with barcode support. Built with Next.js 16, React 19, TypeScript, and Tailwind CSS 4. Self-hosted via Docker Compose with PostgreSQL. Targeting public launch — anyone can sign up, manage cards, and optionally pay for premium features.

## Core Value

Users can reliably store and retrieve their loyalty cards — including barcodes that scan at the register — even when offline.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

- ✓ User registration and login with email/password — existing
- ✓ Card CRUD (create, read, update, delete) with retailer name, notes, barcode — existing
- ✓ Barcode scanning via camera (ZXing) and barcode display (bwip-js) — existing
- ✓ Automatic color extraction from card logos for card theming — existing
- ✓ Brand logo search via Clearbit + logo.dev with caching — existing
- ✓ Light/dark mode with DB-persisted preference — existing
- ✓ Stripe subscription scaffolding (FREE tier auto-created) — existing
- ✓ PWA manifest and basic service worker registration — existing
- ✓ Docker containerization with standalone Next.js output — existing

### Active

<!-- Current scope. Building toward these. -->

- [ ] All known bugs fixed (orphaned images, infinite redirect on skip, silent barcode failures)
- [ ] Security hardened (file upload MIME validation, rate limiting on auth)
- [ ] Dead code removed (onboardingComplete, empty email verification dirs, extractColorsFromUrl stub)
- [ ] Code duplication eliminated (barcode scanning hook, brand logo caching helper)
- [ ] Deprecated APIs migrated (useFormState → useActionState)
- [ ] Performance fixed (JWT callback DB queries, theme preference via cookie)
- [ ] Stripe payments fully working with feature gating infrastructure
- [ ] Subscription page UX fixed (free is obvious default, skip bug resolved)
- [ ] Proper offline PWA (service worker caches cards and barcodes for store use)
- [ ] Account management (user can delete account and all data, GDPR compliance)
- [ ] Polished error states and UX throughout (barcode render failures, upload errors, form validation)
- [ ] Production-grade quality (anyone signs up and it just works)

### Out of Scope

- OAuth/social login — email/password sufficient for v1
- Mobile native app — PWA covers mobile use case
- Multi-language/i18n — English only for launch
- Admin dashboard — single-tenant, no admin needed
- Real-time features — cards are static data, no need for websockets
- Card sharing between users — personal card storage only

## Context

This is a brownfield project. The application works end-to-end but has significant quality issues: zero test coverage, multiple real bugs, code duplication, dead code, security gaps, performance bottlenecks, and incomplete features (Stripe payments, PWA offline). The codebase was developed iteratively without cleanup passes.

Key technical context:
- NextAuth v5 beta — auth works but the beta status means careful dependency management
- Stripe integration uses SubscriptionService static class pattern — well-structured but untested
- Card images stored on local filesystem (public/uploads/) — requires volume mount in Docker
- Barcode scanning uses @zxing/browser 0.1.5 (pre-1.0, unmaintained wrapper) — core feature depends on fragile dependency
- No test framework installed — zero automated tests anywhere

Codebase map available at `.planning/codebase/` with detailed analysis of architecture, stack, conventions, concerns, and structure.

## Constraints

- **Tech stack**: Next.js 16 / React 19 / TypeScript / Tailwind CSS 4 / Prisma / PostgreSQL — committed, no framework changes
- **Self-hosted**: Docker Compose deployment, no Vercel/cloud platform dependencies
- **Storage**: Local filesystem for images (no S3/cloud storage for v1)
- **Auth**: NextAuth v5 credentials provider only
- **Payments**: Stripe — already integrated, extend don't replace

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Keep Stripe with free + paid tiers | Already scaffolded, user wants real payments | — Pending |
| Feature gates TBD | User unsure what to gate — build infrastructure first, decide gates later | — Pending |
| Offline PWA required | Users need cards at the store without network — core value | — Pending |
| Fix subscription page, don't remove it | Keep plan selection flow but make free the obvious path | — Pending |
| Cookie-based theme preference | Eliminates DB query on every page load for dark mode | — Pending |
| Extract barcode scanning to shared hook | Eliminates ~200 lines of duplication between add/edit forms | — Pending |

---
*Last updated: 2026-02-28 after initialization*
