# Feature Research

**Domain:** Loyalty/store card management PWA with freemium subscription model
**Researched:** 2026-02-28
**Confidence:** MEDIUM-HIGH (competitor analysis verified; UX patterns from multiple authoritative sources; loyalty card app ecosystem verified via search)

---

## Context: What Already Exists

This is a brownfield upgrade project. The following are already shipped:

- Card CRUD with barcode scan (ZXing) and display (bwip-js)
- Registration / login (credentials, bcrypt)
- Brand logo search + color extraction
- Light/dark mode
- Stripe scaffolding (FREE tier auto-created; paid plans "Coming Soon")
- Basic PWA manifest + a minimal service worker
- Docker + PostgreSQL self-hosted deployment
- Settings page with sign-out (no account deletion)

The research below focuses on what is **missing** to reach production quality, organized by category.

---

## Feature Landscape

### Table Stakes (Users Expect These)

Features users assume exist in any loyalty card or freemium SaaS product. Missing these means the product feels broken or untrustworthy.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Offline card access with barcode display** | Core value proposition: users pull out their phone at the register — no signal in many stores. Every major competitor (Stocard, Key Ring, SuperCards) works offline. | MEDIUM | Current SW caches uploads (images) but does NOT cache card page HTML/data. Dashboard requires a network round-trip. Must cache card list and individual card routes. |
| **Offline indicator UI** | Users need to know the app is in offline mode vs network error. Without this, stale data looks like a broken app. | LOW | Add a banner/badge that appears when `navigator.onLine === false`. |
| **Subscription cancel self-service** | Any paid SaaS must let users cancel without contacting support. GDPR and card network rules mandate it. API route already exists (`/api/subscription/cancel`) but no UI exists. | LOW | Wire up cancel button in settings; confirm modal; "active until [date]" state. |
| **Subscription status visibility** | Users on free plan should know their tier; paid users should see renewal date and plan details. | LOW | `/api/subscription/status` already exists. Needs a UI card in settings. |
| **Account deletion (GDPR Article 17)** | GDPR enforcement of Right to Erasure is a 2025 EU priority (EDPB Coordinated Enforcement Framework). Self-hosted product with EU users must support this. Any app that allows account creation must allow in-app deletion (Apple App Store requirement since 2022; Google Play since 2023). | MEDIUM | Must delete: User row, all Cards, all uploaded files in `public/uploads/`, Stripe customer (cancel subscription first), BrandLogo cache rows where no other user references them. Must be irreversible with confirmation step. |
| **Meaningful error messages on barcode failure** | Barcode scanning fails silently today. Users at the register need actionable feedback: "Camera permission denied — enable in browser settings" vs "Could not read barcode — try better lighting". | LOW | Categorize ZXing error types; show inline feedback with remediation hint. |
| **Form validation with inline errors** | Standard expectation on any registration/login/card form. Missing = product feels amateur. Validate on blur (not on keystroke); show errors next to the offending field (not a generic toast). | LOW | Register and card forms have basic server errors. Need client-side inline validation with human-readable messages. |
| **Empty state for no cards** | A brand new user landing on an empty dashboard needs direction. "You have no cards yet — add your first card" with a prominent CTA. Currently unexplored; likely shows an empty list. | LOW | Single empty-state component with illustration and CTA. |
| **Rate limiting on authentication endpoints** | Without rate limiting, registration and login are vulnerable to brute force and credential stuffing. Basic security hygiene for any public-facing auth. | MEDIUM | Apply at middleware layer or Next.js API route; use in-memory or Redis-backed counters. Simple: 5 attempts per IP per 15 minutes. |
| **File upload MIME/content validation** | Currently accepts any file as a card image. Users could upload non-image files; malicious actors could attempt file-based attacks. | LOW | Validate MIME type server-side (not just client `accept` attribute). Reject non-image types with clear error. |

### Differentiators (Competitive Advantage)

Features that set this product apart. Not universally expected, but meaningfully valuable to users.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Feature gating infrastructure (centralized permissions)** | Not a user-facing feature, but the enabling layer for a real freemium business. Without it, paid plans are vaporware. Build a `permissions.ts` module keyed on subscription tier that all components/actions consult. | MEDIUM | Pattern: centralized `canDo(userId, 'feature_name')` or `getPermissions(tier)` that returns capability flags. Gate enforcement in both Server Actions (mutation prevention) and Server Components (UI rendering). No need to decide what to gate yet — just build the infrastructure. |
| **Stripe Customer Portal redirect** | Rather than building a custom billing UI, link to the Stripe-hosted Customer Portal for plan upgrades, payment method updates, and invoice history. Industry standard; Stripe maintains compliance with SCA, PSD2, Visa rule changes automatically. | LOW | Create a `/api/create-portal-session` route. Add "Manage Billing" button in settings. Requires configured portal in Stripe Dashboard. |
| **Card sort/search** | Once a user has 10+ cards, unsorted lists become unusable. Sort by last used, alphabetical, or custom order. Search by retailer name. Competitor SuperCards does alphabetical + last-used sorting. | MEDIUM | Sort is a server query (Prisma `orderBy`). Search is client-side filtering on the fetched list for small collections. |
| **Graceful barcode fallback display** | When bwip-js fails to render a barcode (invalid format, unsupported type), show the raw barcode number with copy-to-clipboard instead of a blank space. Some cashiers can manually enter the number. | LOW | Wrap Barcode component in error boundary; render numeric fallback with copy button on error. |
| **PWA install prompt** | Prompt users to "Add to Home Screen" for a native-like experience. Competitors are native apps; the install prompt closes the gap. | LOW | Listen for `beforeinstallprompt` event; show a custom "Install App" button at appropriate time (after first successful card view). |
| **Offline-added card queue (deferred)** | Users discover they forgot to add a card when already at the store without signal. Allow card creation offline with sync when connectivity returns. | HIGH | Requires IndexedDB write + Background Sync API + conflict resolution on sync. Defer to v2 — high complexity, low frequency use case for read-heavy app. |

### Anti-Features (Commonly Requested, Often Problematic)

Features that seem logical but should be explicitly avoided in this milestone.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| **OAuth / social login** | "Sign in with Google is easier" | Increases dependency surface; adds OAuth complexity; out-of-scope per PROJECT.md; NextAuth v5 beta adds risk surface | Email/password is sufficient; focus on fixing existing auth quality |
| **Card sharing between users** | "Share my Costco card with family" | Requires permissions model, shared ownership semantics, invite flows — 3x the complexity of the base feature | Personal card storage only; scope decision already made in PROJECT.md |
| **Real-time points balance sync** | "Show my current points" | Requires retailer API integrations (none are public/standardized), scraping (fragile), or user-entered values (no UX win over current notes field) | Notes field already exists for balance tracking; out of scope |
| **Push notifications for offers** | "Notify me when [store] has a sale" | Requires retailer data feeds, browser push permission, and notification infrastructure — unrelated to core card storage value | Not planned; would require a different product direction |
| **Admin dashboard** | "Manage users, see stats" | Single-tenant self-hosted product; no admin need. Building it would distract from user-facing quality work. | Stripe Dashboard covers billing metrics; Prisma Studio covers DB inspection in dev |
| **Custom barcode ordering UI (drag-and-drop)** | "I want to reorder my cards manually" | Heavy client-side state management; complex with SSR; sort-by-last-used achieves the practical goal automatically | Implement automatic sort-by-last-used first; evaluate need after launch |
| **i18n / multi-language** | "Support other languages" | Doubles copy maintenance overhead, adds tooling complexity, no clear user demand at launch | English-only for v1; per PROJECT.md constraint |
| **Email verification on registration** | "Verify email before access" | The empty `email-verification` directories are already dead code. Implementation is incomplete and adds user friction for a self-hosted app where the user base is controlled. | Delete the stub; rely on registration quality and rate limiting instead |

---

## Feature Dependencies

```
[Rate Limiting on Auth]
    └──required before──> [Public Launch]

[File Upload MIME Validation]
    └──required before──> [Public Launch]

[Account Deletion]
    └──requires──> [Card file cleanup on delete]
    └──requires──> [Stripe cancel-before-delete flow]
    └──requires──> [Confirmation modal UX]

[Feature Gating Infrastructure]
    └──required before──> [Paid Plan Activation]
    └──required before──> [Stripe Customer Portal]

[Stripe Customer Portal]
    └──requires──> [Feature Gating Infrastructure]
    └──requires──> [Stripe portal configured in Dashboard]

[Subscription Status UI]
    └──requires──> [/api/subscription/status already exists — just needs UI]

[Subscription Cancel UI]
    └──requires──> [/api/subscription/cancel already exists — just needs UI]

[Offline Card Access]
    └──requires──> [Service worker cache card pages + data]
    └──enhances──> [Offline Indicator UI]

[Offline Indicator UI] ──enhances──> [Offline Card Access]

[Card Sort/Search] ──enhances──> [Empty State UX] (search results can be empty)

[Barcode Fallback Display]
    └──requires──> [Error boundary around Barcode component]
```

### Dependency Notes

- **Feature Gating Infrastructure requires no prior features** but must be built before any paid plan is turned on. Build the infrastructure first; decide what to gate after.
- **Account Deletion requires Stripe cancel-before-delete**: if a user has an active paid subscription, it must be cancelled in Stripe before deleting the local user record. The `SubscriptionService.cancelSubscription` method exists — call it in the deletion flow.
- **Offline Card Access is independent of subscription**: it must work for all users, including free tier. Offline is the core value promise of the product.
- **Subscription Cancel UI and Status UI are low-effort**: both API routes already exist. These are UI-only tasks that unblock the billing UX.

---

## MVP Definition

This is a brownfield upgrade — the product already functions. "MVP" here means "minimum changes to reach production quality."

### Launch With (Production Milestone)

These are required before any public users sign up:

- [ ] **Offline card access** — users need their cards at the register, no network required. The current SW is insufficient; card data must be cached.
- [ ] **Account deletion (GDPR)** — legal requirement for EU-accessible product; App Store and Play Store requirement for any app with account creation.
- [ ] **Rate limiting on auth** — basic security hygiene before public launch.
- [ ] **File upload MIME validation** — security requirement; prevent non-image uploads.
- [ ] **Meaningful barcode error messages** — the core feature must give useful feedback on failure, not silent nothing.
- [ ] **Inline form validation** — table stakes UX quality for registration and card forms.
- [ ] **Empty state for card list** — required for first-run experience to feel complete.
- [ ] **Subscription status + cancel UI** — API exists; users must be able to see and manage their subscription without contacting support.

### Add After Production Stability (v1.x)

- [ ] **Feature gating infrastructure** — build once Stripe payments are validated working end-to-end.
- [ ] **Stripe Customer Portal** — after feature gating; low effort but requires portal configured in Stripe Dashboard first.
- [ ] **Offline indicator UI** — polish pass after core offline caching is working.
- [ ] **Barcode fallback display** — polish pass; requires error boundary work.
- [ ] **Card sort/search** — add when early users report card management friction (data-triggered).
- [ ] **PWA install prompt** — polish; adds perceived quality after core features work.

### Future Consideration (v2+)

- [ ] **Offline card creation queue** — high complexity (IndexedDB + Background Sync); low-frequency use case for a read-heavy app.
- [ ] **What to gate behind paid tiers** — explicitly deferred. Build infrastructure now; decide gate points based on user feedback after launch.

---

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Offline card access (SW caching of card pages) | HIGH | MEDIUM | P1 |
| Account deletion (GDPR) | HIGH | MEDIUM | P1 |
| Rate limiting on auth | HIGH | MEDIUM | P1 |
| File upload MIME validation | HIGH | LOW | P1 |
| Barcode error messages | HIGH | LOW | P1 |
| Inline form validation | HIGH | LOW | P1 |
| Empty state (no cards) | MEDIUM | LOW | P1 |
| Subscription cancel UI | HIGH | LOW | P1 |
| Subscription status UI | MEDIUM | LOW | P1 |
| Feature gating infrastructure | HIGH | MEDIUM | P2 |
| Stripe Customer Portal | MEDIUM | LOW | P2 |
| Offline indicator UI | MEDIUM | LOW | P2 |
| Barcode fallback (copy number) | MEDIUM | LOW | P2 |
| Card sort/search | MEDIUM | MEDIUM | P2 |
| PWA install prompt | LOW | LOW | P2 |
| Offline card creation queue | LOW | HIGH | P3 |
| What to gate (tier design) | MEDIUM | LOW | P3 |

**Priority key:**
- P1: Must have for production launch
- P2: Should have; add in first follow-up milestone
- P3: Future consideration; defer until after validation

---

## Competitor Feature Analysis

| Feature | Stocard (acquired by Klarna) | SuperCards (Stocard successor) | Key Ring | StoreCard (this project) |
|---------|------------------------------|-------------------------------|----------|--------------------------|
| Offline access | Yes — core promise | Yes | Yes | Partial (images cached; page data not) |
| Barcode display | Yes | Yes | Yes | Yes |
| Barcode scan | Yes (camera) | Yes | Yes | Yes (ZXing) |
| Manual card entry | Yes | Yes | Yes | Yes |
| Sort/search | Yes (last used, alpha) | Yes (alpha, last used, frequency) | Yes | No |
| Account deletion | Yes | Yes | Yes | No — missing |
| Subscription management | Klarna-integrated | Free, no subscription | Ad-supported free | Scaffold only |
| Offline indicator | Yes | Yes | Not researched | No |
| Brand logos | Yes | Yes (custom icons) | Partial | Yes (Clearbit/logo.dev) |
| Dark mode | Yes | Yes | Not researched | Yes |
| Notes per card | Not confirmed | Yes | Partial | Yes (nerd mode) |
| PWA / web version | No (native only) | No (native only) | No (native only) | Yes — differentiator |

**Key competitive insight:** All major competitors are native apps, not PWAs. StoreCard's PWA approach is itself a differentiator — but only if offline works reliably. A PWA that requires a network connection to show cards is worse than a native app, not better.

---

## Offline Experience: Specific Requirements

Based on research into PWA caching patterns and the app's Next.js App Router architecture, offline card access requires:

1. **Cache card list page (`/dashboard`)** — network-first with cache fallback; acceptable to show slightly stale data offline.
2. **Cache individual card pages (`/cards/[id]`)** — cache-first after first visit; barcode must render from cached HTML.
3. **Cache card images (`/uploads/*`)** — already done in the current SW (cache-first).
4. **Cache app shell (JS/CSS bundles, fonts)** — precache at install; currently only caches 3 static assets.
5. **Do NOT attempt to cache auth routes or POST requests** — skip these in the fetch handler.
6. **Offline fallback page** — if a user navigates to a page not yet cached, show a branded offline page rather than a browser error.

The current `sw.js` has the correct architectural pattern (network-first with cache fallback) but does not cache the Next.js page bundles or API data responses. Extending it to precache the built JS/CSS chunks and runtime-cache dashboard/card routes is the required work.

**Confidence:** MEDIUM. The App Router's RSC architecture means HTML responses contain server-rendered data. Caching the full page response (not just the shell) will serve stale card data when offline. This is acceptable for a read-only offline use case. Verified via official Next.js PWA discussions and Workbox documentation.

---

## Subscription Management: Specific Requirements

The Stripe scaffolding is in place. What's missing is the user-facing management surface:

1. **Subscription status card in settings** — show: current tier (Free/Monthly/Yearly), next billing date (if paid), status (active/cancelled/past_due). Reads from `/api/subscription/status`.
2. **Cancel subscription button** — in settings, behind a confirmation modal ("Your subscription will remain active until [date]"). Calls `/api/subscription/cancel`. Show success state.
3. **Stripe Customer Portal link** — "Manage billing, update payment method, view invoices" links out to Stripe's hosted portal. Requires `/api/create-portal-session` route returning a redirect URL.
4. **Webhook handling for cancellation and payment failure** — already scaffolded; verify all events update DB state correctly so UI reflects reality.

**Confidence:** HIGH. Official Stripe documentation confirms Customer Portal approach. All API routes are partially implemented.

---

## Account Management / GDPR: Specific Requirements

GDPR Right to Erasure (Article 17) is an EU enforcement priority in 2025 per EDPB announcement. Even for a self-hosted product, if EU users sign up, compliance is required.

Deletion must be complete and irreversible:

1. Cancel active Stripe subscription (if any) before deleting customer record.
2. Delete Stripe Customer object (or at minimum detach all payment methods).
3. Delete all `Card` rows owned by the user.
4. Delete all files in `public/uploads/` associated with those cards.
5. Delete `BrandLogo` rows only if no other user references the same domain (shared cache — check references first).
6. Delete `Subscription` row.
7. Delete `User` row.
8. Sign the user out and redirect to the landing page.

Implementation pattern: a `deleteAccount` Server Action in `actions.ts` that handles the full cascade. Expose via a "Delete Account" button in settings behind a two-step confirmation ("Type DELETE to confirm" or modal with explicit confirmation).

**Confidence:** MEDIUM. GDPR requirements are well-documented. The cascade order (Stripe first, then local data) is confirmed via Stripe documentation patterns. The specific 30-day response window under GDPR Article 17 is less relevant for a self-service in-app flow (immediate deletion is better).

---

## Error Handling UX: Specific Requirements

Current state: Server Actions return error strings that components display. Silent failures for image upload and logo caching. No client-side validation.

Required improvements:

1. **Barcode scan errors** — categorize: `PermissionDenied`, `CameraNotFound`, `DecodeFailure`. Show inline message with specific remediation text (not a generic "failed").
2. **Form validation (client-side)** — validate on field blur. Show error text directly below the offending field. Keep submit button enabled (do not disable on invalid state). Error copy must be human, not technical.
3. **Image upload errors** — currently silent. Show a non-blocking toast or inline error when image processing fails. Do not block card creation.
4. **Network errors (offline)** — when an action fails because offline, show "You're offline — changes will not save" rather than a generic error.
5. **Empty states** — dashboard with no cards: show illustration + "Add your first card" CTA button. Search with no results: "No cards match [query]" with clear search button.
6. **Loading states** — all buttons that trigger Server Actions must show a pending state (spinner or text "Saving..."). The subscribe page already does this (`useFormStatus`); replicate pattern everywhere.

**Confidence:** HIGH. NN/g and Material Design guidelines are authoritative sources. The patterns are industry-standard.

---

## Sources

- [MDN: Progressive Web Apps — Offline & Service Workers](https://developer.mozilla.org/en-US/docs/Web/Progressive_web_apps/Guides/Caching) — HIGH confidence
- [Stripe: Customer self-service with a customer portal](https://docs.stripe.com/customer-management) — HIGH confidence (official Stripe docs)
- [Stripe: Configure the customer portal](https://docs.stripe.com/customer-management/configure-portal) — HIGH confidence
- [GDPR.eu: Right to be Forgotten](https://gdpr.eu/right-to-be-forgotten/) — HIGH confidence
- [CompliancePoint: GDPR Right to Erasure an Enforcement Priority in 2025](https://www.compliancepoint.com/privacy/gdpr-right-to-erasure-an-enforcement-priority-in-2025/) — MEDIUM confidence
- [Orb: What is feature gating? 2025](https://www.withorb.com/blog/feature-gating) — MEDIUM confidence
- [DEV Community: Feature Gating — How We Built a Freemium SaaS Without Duplicating Components](https://dev.to/aniefon_umanah_ac5f21311c/feature-gating-how-we-built-a-freemium-saas-without-duplicating-components-1lo6) — MEDIUM confidence
- [MakerKit: Subscription Permissions — Next.js Supabase SaaS Kit](https://makerkit.dev/docs/next-supabase/organizations/subscription-permissions) — MEDIUM confidence
- [NN/g: 10 Design Guidelines for Reporting Errors in Forms](https://www.nngroup.com/articles/errors-forms-design-guidelines/) — HIGH confidence
- [Fishtank: Building Native-Like Offline Experience in Next.js PWAs](https://www.getfishtank.com/insights/building-native-like-offline-experience-in-nextjs-pwas) — MEDIUM confidence
- [Next.js GitHub Discussion: Offline-First Next.js 15 App with App Router](https://github.com/vercel/next.js/discussions/82498) — MEDIUM confidence
- [OptCulture: Top 12 Loyalty Card Apps 2025](https://optculture.com/blogs/post/loyalty-card-apps-reviews/) — LOW confidence (single source competitor analysis)
- AlternativeTo: Stocard alternatives — LOW confidence (community aggregator)

---

*Feature research for: loyalty/store card management PWA (brownfield production upgrade)*
*Researched: 2026-02-28*
