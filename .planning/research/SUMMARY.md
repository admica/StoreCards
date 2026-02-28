# Project Research Summary

**Project:** StoreCard — loyalty/store card management PWA
**Domain:** Brownfield production hardening — Next.js PWA, self-hosted, freemium SaaS
**Researched:** 2026-02-28
**Confidence:** MEDIUM-HIGH

## Executive Summary

StoreCard is a functional loyalty card PWA that needs production hardening before public launch, not a greenfield build. The core value proposition — pulling up a barcode at the store register — currently fails offline because the service worker does not cache card page routes or their data, only static images. All major competitors (Stocard, Key Ring, SuperCards) are native apps; StoreCard's PWA approach is a genuine differentiator, but only if offline works end-to-end. The recommended approach is to harden the existing stack incrementally: fix the service worker first (Serwist + Turbopack path), then address the two active security gaps (no auth rate limiting, no server-side MIME validation on uploads), then complete the billing surface (subscription UI, account deletion for GDPR compliance), and finally build the feature gating infrastructure that activates the freemium business model.

The stack additions are minimal and well-justified: `@serwist/turbopack` replaces the hand-rolled service worker, `lru-cache` handles in-memory rate limiting for the single-container deployment, `sharp` re-encodes uploads to guarantee image content, and `sonner` adds a unified toast layer. Cookie-based theme preference eliminates a DB query on every root layout render. No new framework or database is introduced — the existing Next.js 16 + Prisma + PostgreSQL + Stripe + NextAuth v5 stack is the right one.

The most dangerous live bugs are the JWT subscription state issue (Stripe webhooks update the DB but active sessions never see it, so paying users can appear locked out or cancelled users retain access) and the "Skip for now" infinite redirect loop on the subscribe page. Both must be fixed before any paid plan is activated. GDPR account deletion is a legal requirement for EU-accessible products and is missing entirely. The recommended phase order is: Bug Fixes and Security first (unblocks safe public launch), then PWA Offline (delivers core value promise), then Subscription and Billing UI (completes the revenue surface), and finally Feature Gating Infrastructure (enables the freemium model).

## Key Findings

### Recommended Stack

The existing framework is not changed. Four targeted additions address the four upgrade areas. For offline PWA: `@serwist/turbopack` (not `@serwist/next`) is required because Next.js 16 defaults to Turbopack in dev — the webpack plugin variant will silently produce no service worker. `idb` provides the IndexedDB wrapper if offline card writes are ever needed. For security: `sharp` serves dual duty — it validates uploads by attempting image decode and re-encodes to WebP, stripping any embedded payloads, and is already recommended by Next.js for image optimization. `lru-cache` provides in-memory rate limiting; Redis is unnecessary overhead for a single Docker container. For error UX: `sonner` is the zero-dependency toast library used by shadcn/ui with native dark mode support. For performance: no new library — cookie-based theme reads via `cookies()` from `next/headers` eliminate the DB call in root layout, and the JWT callback over-refresh is a pure code fix.

**Core additions:**
- `@serwist/turbopack` + `serwist`: Turbopack-aware Workbox fork for Next.js 16 service worker — use this, not `next-pwa` (unmaintained) or `@serwist/next` (Webpack only)
- `sharp@^0.34.5`: Image upload validation + re-encode sanitization — replaces client-side MIME checks that are trivially bypassable
- `lru-cache@^11.x`: In-memory rate limiting store — appropriate for single Docker instance; replace with Redis only if horizontal scaling is added
- `sonner@^2.0.7`: Toast notifications — zero deps, React 19 compatible, native dark mode

**Do not install:** `next-pwa` (shadowwalker, unmaintained), `@upstash/ratelimit` (requires Redis), `express-rate-limit` (Express context, not Next.js Server Actions), `file-type` v21 (requires Node 20+; Docker base is Node 18).

### Expected Features

This is a brownfield upgrade. "Must have" means missing gaps that block production quality, not features to build from scratch.

**Must have (production blockers):**
- Offline card access with barcode display — the core use case fails today; SW caches images but not page routes
- Account deletion (GDPR Article 17) — legal requirement; also required by Apple App Store and Google Play since 2022-2023
- Rate limiting on auth endpoints — basic security hygiene before public launch; currently absent
- File upload server-side MIME validation — `file.type` is client-controlled and bypassable; requires magic bytes + sharp re-encode
- Meaningful barcode scan error messages — fails silently today; categorize errors with actionable copy
- Inline form validation — client-side on-blur validation with field-level errors; currently only server errors
- Empty state for card list — first-run experience shows nothing; needs CTA
- Subscription cancel UI + status UI — API routes already exist; only UI is missing

**Should have (v1.x after stable launch):**
- Feature gating infrastructure — centralized `permissions.ts` / `requireFeature()` before activating paid plans
- Stripe Customer Portal link — delegates billing management to Stripe's hosted portal; low effort
- Offline indicator UI — banner when `navigator.onLine === false`; needed alongside offline caching
- Barcode fallback display — raw number + copy button when bwip-js fails to render
- Card sort/search — sort by last used / alpha; search by name; add when users report friction
- PWA install prompt — trigger after first card added

**Defer (v2+):**
- Offline card creation queue — IndexedDB write + Background Sync + conflict resolution; high complexity for a read-heavy app
- What to gate behind paid tiers — decide after launch validation, not before
- OAuth/social login, card sharing, push notifications, admin dashboard — explicitly anti-features for this milestone

### Architecture Approach

The architecture is an additive layer on the existing App Router structure. Four new abstractions plug into the current system: a Serwist service worker (`app/sw.ts` compiled at build time) handles offline caching with cache-first for `/uploads/*` and network-first with offline fallback for navigation; `lib/feature-gate.ts` provides a `requireFeature()` function memoized with React `cache()` that enforces subscription tier from the DB — never from JWT; `lib/rate-limit.ts` is a module-level Map-based limiter checked in middleware for auth routes; and `app/lib/cookie-actions.ts` is a Server Action that writes the theme cookie, replacing the current `auth()` + DB query in root layout.

**Major components:**
1. Service Worker (`app/sw.ts`): Precaches static assets and JS bundles; runtime-caches card pages (network-first) and card images (cache-first); handles offline fallback page; versioned cache key tied to build ID to prevent stale app versions
2. Feature Gate (`lib/feature-gate.ts`): Single `requireFeature(feature)` entry point; DB-authoritative tier check memoized per request; called at the top of every gated Server Action AND in Server Components for UI rendering; never reads JWT subscription field for enforcement decisions
3. Rate Limiter (`lib/rate-limit.ts`): Module-level Map with TTL; 5 auth attempts per IP per 15 minutes; checked in middleware for login/register routes; returns structured error objects (not HTTP 429) since Server Actions cannot return Response objects
4. Cookie Theme (`app/lib/cookie-actions.ts`): Server Action writes `theme` cookie; root layout reads via `cookies()` with no DB call; eliminates ~20ms per-request DB round-trip

### Critical Pitfalls

1. **Subscription state in JWT used for access control** — Stripe webhooks update the DB, but the user's JWT never refreshes for active sessions. Paying users appear locked out; cancelled users retain access. Fix: feature gate reads subscription tier from DB via `getSubscriptionTier(userId)` (memoized with React `cache()`), never from `session.user.subscription`. JWT carries only user ID.

2. **Service worker serves stale app versions after deploy** — Static cache name means installed PWAs run old code indefinitely. Users on mobile may never see updates. Fix: use Serwist's build-hash-versioned precache manifest; implement `skipWaiting()` + `clients.claim()`; delete old caches in `activate` event. Serwist handles this automatically when configured correctly.

3. **File upload MIME validation is bypassable** — Checking `file.type` is client-controlled. An attacker uploads an HTML file with `Content-Type: image/jpeg`; it lands in `public/uploads/` and is served as a static asset. Fix: read magic bytes from the buffer; pass through `sharp()` to re-encode; only the re-encoded bytes are written to disk.

4. **JWT callback queries DB on every request for new users** — The `needsRefresh` condition fires on `!typedToken.subscriptionSelected`, which is `false` for all new users. Two Prisma queries run on every page load and static file request until the user selects a plan. Fix: change refresh condition to `trigger === 'update'` only.

5. **Client-only feature gates are trivially bypassable** — Hiding UI elements is UX, not security. Any user can call a Server Action directly via `fetch()` in DevTools. Fix: every gated Server Action must call `requireFeature()` at its entry point before performing any work.

6. **"Skip for now" is an infinite redirect loop** — The skip button is a plain `<Link>` that does not set `subscriptionSelected = true`. Users who skip are redirected back to `/subscribe` on every subsequent request. Fix: wire skip to a Server Action that sets `subscriptionSelected = true` then redirects.

## Implications for Roadmap

Based on research, suggested phase structure:

### Phase 1: Bug Fixes and Security Hardening
**Rationale:** Two live bugs (infinite redirect loop, JWT subscription staleness) block any meaningful testing of the billing surface. Three security gaps (no rate limiting, no MIME validation, client-side-only file.type check) must be closed before any public user signs up. These are independent of each other and can be developed in parallel — they share no architectural dependencies.
**Delivers:** A safe, non-broken baseline — auth works reliably, uploads are secure, the subscribe page is navigable.
**Addresses:** Rate limiting on auth, file upload MIME validation (magic bytes + sharp re-encode), skip-for-now redirect fix, JWT callback over-refresh fix, `dangerouslySetInnerHTML` SW script replaced with `next/script`.
**Avoids:** Pitfalls 3, 4, 6 (MIME bypass, JWT DB queries, redirect loop).
**Stack used:** `sharp`, `lru-cache`, `next/script`.
**Research flag:** Standard patterns — no phase research needed.

### Phase 2: UX Quality and Error Handling
**Rationale:** Barcode scanning errors fail silently — the core feature must give actionable feedback. Form validation and empty states are table-stakes UX quality that block the app from feeling trustworthy. These are low-complexity, high-impact changes that unblock user testing without touching the billing or offline systems.
**Delivers:** Categorized barcode error messages, inline form validation on register/login/card forms, empty state for card list, barcode fallback display (raw number + copy button), loading states on all Server Action buttons.
**Addresses:** Barcode error messages, inline form validation, empty state, barcode fallback, `sonner` toast integration for upload errors and network errors.
**Avoids:** Silent failure UX pitfall; blank barcode at register pitfall.
**Stack used:** `sonner`, Zod (already installed) for client-side validation schemas.
**Research flag:** Standard patterns — NN/g error handling guidelines are authoritative, no research needed.

### Phase 3: Cookie Theme and Performance Cleanup
**Rationale:** The root layout currently calls `auth()` + `prisma.user.findUnique` on every page render for theme. Moving to cookie-based theme is a pure performance win with no user-facing regression. Group with other performance fixes (JWT refresh condition, dashboard pagination groundwork) to ship them together as a single clean-up phase.
**Delivers:** Root layout with zero DB calls for theme; JWT refresh only on `trigger === 'update'`; theme cookie Server Action.
**Addresses:** `getInitialTheme()` DB query, JWT callback over-refresh, FOUC-free dark mode without `localStorage`.
**Avoids:** Pitfall 4 (JWT DB queries on every request).
**Stack used:** `cookies()` from `next/headers` (no new install).
**Research flag:** Standard patterns — official Next.js docs cover this directly.

### Phase 4: Subscription and Account Management UI
**Rationale:** Stripe scaffolding exists; API routes for status and cancel exist. What's missing is the user-facing surface. GDPR account deletion is a legal requirement. The Stripe Customer Portal delegating billing management is low-effort and reduces compliance burden. This phase activates the billing UX without yet deciding what features to gate.
**Delivers:** Subscription status card in settings (tier, renewal date, status), cancel subscription button with confirmation modal, Stripe Customer Portal link, account deletion flow (Stripe cancel → file cleanup → cascade DB delete → sign out), delete-file-on-card-update fix.
**Addresses:** Subscription cancel UI, subscription status UI, account deletion (GDPR), Stripe Customer Portal, image file orphan cleanup.
**Avoids:** GDPR enforcement exposure, App Store/Play Store compliance requirement, Pitfall 1 (cascade delete must cancel Stripe before deleting User).
**Stack used:** Existing `SubscriptionService`, `prisma`, `fs.unlink` for file cleanup.
**Research flag:** May benefit from brief phase research on Prisma cascade delete configuration and Stripe Customer Portal session API — both are well-documented but have specific gotchas.

### Phase 5: PWA Offline Support
**Rationale:** Offline card access is the core value proposition. It is implemented last (not first) because Serwist precaches the compiled app shell — the precache manifest must reflect the final, stable JS/CSS output. Building this before the theme, auth, and billing surfaces are finalized would require rebuilding the service worker configuration after every structural change.
**Delivers:** Serwist service worker replacing the hand-rolled `public/sw.js`; network-first caching for `/dashboard` and `/card/[id]` routes; cache-first for `/uploads/*`; build-hash-versioned cache names; offline fallback page; offline indicator banner; PWA install prompt after first card added.
**Addresses:** Offline card access, offline indicator UI, PWA install prompt, stale SW version problem.
**Avoids:** Pitfall 2 (stale build artifacts), Pitfall 5 (barcode broken at register offline), Anti-Pattern 3 (SW caching POST requests), Anti-Pattern 4 (using `@serwist/next` with Turbopack).
**Stack used:** `@serwist/turbopack`, `serwist`, `esbuild` (dev dep), `idb` (if offline queue added later).
**Research flag:** Needs research during planning — Serwist Turbopack guide is new (Next.js 16 specific), and App Router RSC caching behavior interacts with SW in non-obvious ways. Research the `@serwist/turbopack` route handler pattern before writing any SW code.

### Phase 6: Feature Gating Infrastructure
**Rationale:** This is the enabling layer for the freemium business model. It requires knowing that the Stripe subscription state is accurate (Phase 4 settled that) and that the DB is the authoritative source, not the JWT. Build the infrastructure now; decide what to actually gate based on post-launch user feedback.
**Delivers:** `lib/feature-gate.ts` with `requireFeature()` memoized via React `cache()`; `TIER_FEATURES` enum defining capability flags per tier; gate checks added to relevant Server Actions and Server Components; "Upgrade required" error handling in UI; paid plan "Coming Soon" labels removed.
**Addresses:** Feature gating infrastructure, client-only gate bypass prevention.
**Avoids:** Pitfall 1 (JWT-based authorization), Pitfall 6 (client-only gates bypassable via fetch).
**Stack used:** React `cache()` (built-in), `auth()`, Prisma.
**Research flag:** Standard patterns — well-documented SaaS pattern with clear examples in research. No phase research needed.

### Phase Ordering Rationale

- Bug fixes and security (Phase 1) must come first — the subscribe page redirect loop blocks testing of all subsequent billing work, and security gaps cannot ship to public users.
- UX quality (Phase 2) is independent and low-risk — ship early to enable user testing before complex billing or offline work.
- Cookie theme (Phase 3) is a performance win grouped with other cleanup — independent of billing and offline, ships any time after Phase 1.
- Subscription UI (Phase 4) requires Stripe scaffolding to be stable (already is) but must precede feature gating — you need account deletion before activating paid tiers.
- PWA offline (Phase 5) is last among core features because the service worker precaches the compiled build — doing this before the app shell is stable wastes configuration effort.
- Feature gating (Phase 6) is last because it assumes: subscription state is accurate (Phase 4), DB-authoritative checks are established (Phase 1 JWT fix), and the team has decided what to gate (requires post-Phase 4 validation).

### Research Flags

Needs deeper research during planning:
- **Phase 5 (PWA Offline):** `@serwist/turbopack` route handler pattern is Next.js 16-specific and has limited production examples. App Router RSC HTML caching via service worker has subtle interactions with server-rendered data. Research before writing any SW code.
- **Phase 4 (Account Deletion):** Prisma `onDelete: Cascade` configuration for the User → Card/Subscription/BrandLogo relations needs verification against the current schema. Missing cascades will cause foreign key violations on delete.

Standard patterns (skip research-phase):
- **Phase 1 (Bug Fixes/Security):** Magic bytes validation, lru-cache rate limiting, and JWT refresh fix are all well-documented with clear implementation patterns.
- **Phase 2 (UX Quality):** NN/g error handling, Sonner integration, and inline form validation are established patterns.
- **Phase 3 (Cookie Theme):** Official Next.js docs cover `cookies()` in layout directly.
- **Phase 6 (Feature Gating):** The `requireFeature()` pattern with React `cache()` memoization is well-documented in the architecture research with a complete implementation example.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | MEDIUM-HIGH | All library choices verified against official docs and npm registry. The one uncertainty is `@serwist/turbopack` maturity — it's new for Next.js 16 and has limited production case studies. |
| Features | MEDIUM-HIGH | Must-have features verified via competitor analysis and GDPR/App Store compliance requirements. Feature prioritization is opinionated but based on sound reasoning. |
| Architecture | HIGH | All patterns verified against official Next.js, Serwist, and Stripe documentation. Live code review confirmed the specific bugs and gaps. |
| Pitfalls | HIGH | Critical pitfalls 1, 3, 4, and 6 were confirmed by reading the actual codebase. Pitfall 2 and 5 are well-documented SW patterns with multiple corroborating sources. |

**Overall confidence:** MEDIUM-HIGH

### Gaps to Address

- **Serwist Turbopack production behavior:** The `@serwist/turbopack` route handler pattern (`app/serwist/[path]/route.ts`) is the recommended path for Next.js 16, but it has fewer production examples than the webpack variant. Validate with a spike build before committing Phase 5 to the roadmap timeline.
- **What to gate behind paid tiers:** Explicitly deferred. Research identified the infrastructure pattern but the business decision (card count limit? export feature? logo search?) requires post-launch user data. Plan Phase 6 as infrastructure-only; gate decisions are a separate discovery item.
- **Prisma cascade delete schema:** The schema must have `onDelete: Cascade` on User → Card, User → Subscription, and conditionally User → BrandLogo relations. Verify current schema state before writing the account deletion action.
- **Dashboard pagination:** Research flagged that fetching all cards without pagination breaks at 50+ cards. Not critical for launch (users will have few cards initially) but should be on the v1.x backlog.

## Sources

### Primary (HIGH confidence)
- Next.js official PWA guide — https://nextjs.org/docs/app/guides/progressive-web-apps
- Next.js `cookies()` API reference — https://nextjs.org/docs/app/api-reference/functions/cookies
- Serwist Turbopack quick-start — https://serwist.pages.dev/docs/next/turbo
- Stripe Customer Portal docs — https://docs.stripe.com/customer-management
- Stripe webhook best practices — https://docs.stripe.com/billing/subscriptions/webhooks
- GDPR Right to Erasure — https://gdpr.eu/right-to-be-forgotten/
- Live codebase audit — `/home/autopcap/storecard/.planning/codebase/CONCERNS.md`

### Secondary (MEDIUM confidence)
- FreeCodeCamp in-memory rate limiter (Jan 2026) — confirmed `lru-cache` pattern for Next.js single-instance
- Serwist v9 blog post — ESM-only, Node 18+, Webpack optional peer dep
- LogRocket Next.js 16 PWA offline support (Jan 2026) — App Router offline patterns
- NextAuth JWT refresh issue (Medium, Clerk articles) — JWT subscription staleness behavior
- CompliancePoint GDPR Right to Erasure 2025 enforcement priority — compliance urgency

### Tertiary (LOW confidence)
- OptCulture Top 12 Loyalty Card Apps 2025 — competitor feature comparison (single-source)
- AlternativeTo: Stocard alternatives — community aggregator, used only to validate competitor landscape

---
*Research completed: 2026-02-28*
*Ready for roadmap: yes*
