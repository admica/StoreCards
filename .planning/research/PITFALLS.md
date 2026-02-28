# Pitfalls Research

**Domain:** Loyalty card PWA — brownfield Next.js upgrade (offline support, Stripe payments, security hardening)
**Researched:** 2026-02-28
**Confidence:** HIGH (codebase-specific issues verified against live code); MEDIUM (ecosystem patterns, multiple sources confirmed)

---

## Critical Pitfalls

### Pitfall 1: Subscription State Lives in JWT — Webhook Updates Are Invisible to Active Sessions

**What goes wrong:**
Stripe webhooks update the database correctly, but the user's active session still holds the old subscription state in their JWT cookie. A user who upgrades from FREE to PAID sees no change in feature access until they log out and back in. Conversely, a cancelled subscription appears active for the entire remaining JWT lifetime. The current `auth.config.ts` only refreshes the token on `trigger === 'update'` or when `subscriptionSelected`/`subscription` is missing — neither condition fires after a webhook.

**Why it happens:**
NextAuth JWT strategy is stateless by design. The encrypted cookie is self-contained; there is no mechanism for server-side events to invalidate or update an existing cookie without the client re-authenticating. Developers assume "webhook updates DB → feature gates work" without accounting for the JWT layer between DB truth and request-time access checks.

**How to avoid:**
Do NOT read `session.user.subscription` for access-control decisions. Instead, at the point of feature gate evaluation, fetch subscription status fresh from the database (or a short-lived server-side cache). The JWT should carry only the minimum identity data (user ID). The subscription check becomes a DB query gated by user ID, not a JWT field read. This is already safe because feature gates only run server-side.

Separately, after a successful checkout redirect, force a session refresh using NextAuth's `unstable_update` to ensure the JWT reflects the new subscription within the current session.

**Warning signs:**
- Feature gates read `session.user.subscription.tier` or `session.user.subscription.isActive` directly
- No DB query in the feature gate code path
- Users report that paying doesn't unlock features without re-login
- Cancelled subscriptions still grant paid access

**Phase to address:** Stripe Payments & Feature Gating phase — before any feature gate code is written, establish the pattern of DB-authoritative subscription checks.

---

### Pitfall 2: Service Worker Caches Next.js Build Artifacts and Serves Stale App Versions

**What goes wrong:**
After deploying a new version, users with an installed PWA continue to see the old app because the service worker is still serving cached `.next/static/` chunks from the previous build. The new service worker installs in the background but waits for all tabs to close before activating. On a mobile device that never fully closes the browser, this can mean users run old code for weeks.

The existing service worker in `app/layout.tsx` is injected via `dangerouslySetInnerHTML` and is a custom implementation. Without a versioned cache key that changes on each build, it will never evict stale assets.

**Why it happens:**
Developers add a service worker for offline support, verify it works in the browser, and ship it. They don't test the update flow: deploy new build → existing user → expect updated app. The browser's SW lifecycle (install → wait → activate) is not intuitive, and `skipWaiting` is an opt-in.

**How to avoid:**
Use a build-hash-versioned cache name (e.g., `storecard-v${BUILD_ID}`) so each deployment creates a new cache. Implement `skipWaiting()` in the `install` event to activate immediately, combined with `clients.claim()` in `activate`. Delete all caches not matching the current version in the `activate` event. Consider using Serwist (the maintained Workbox fork) rather than hand-rolling the SW, as it handles precache manifest generation per build automatically.

**Warning signs:**
- Cache name is a static string (e.g., `"storecard-cache"`) not tied to a build identifier
- No `activate` event handler deleting old caches
- No `skipWaiting()` call
- Deploying new JS changes without the service worker noticing

**Phase to address:** PWA Offline Support phase — the SW must be built correctly from the start; retrofitting cache versioning after deployment is painful.

---

### Pitfall 3: File Upload MIME Validation Relies on the `File.type` Header (Bypassable)

**What goes wrong:**
The current upload code in `actions.ts` checks only file size, not type. Even if MIME type validation is added by checking `file.type`, this is trivially bypassable: an attacker sets the `Content-Type` to `image/jpeg` while the file body is an SVG with embedded JavaScript, an HTML file, or a PHP webshell. The browser reports whatever the attacker sets. Files land in `public/uploads/` and are served as static assets by Next.js — an uploaded `.html` file is rendered by the browser.

**Why it happens:**
Developers add `if (file.type !== 'image/jpeg') return error` and consider the validation complete. The distinction between the declared MIME type (client-controlled) and the actual file content (what you need to check) is not obvious.

**How to avoid:**
Read the first 12 bytes of the uploaded buffer and check against known magic byte signatures for permitted formats (JPEG: `FF D8 FF`, PNG: `89 50 4E 47`, WebP: `52 49 46 46 ... 57 45 42 50`). Do this before writing to disk. Then pass the buffer through `sharp()` to re-encode as WebP or JPEG — this sanitizes the content since `sharp` parses and re-renders the pixel data, stripping any embedded scripts. The output file is never the original bytes the attacker submitted.

```typescript
// Correct pattern: magic bytes + re-encode, not file.type
const buffer = Buffer.from(await file.arrayBuffer())
const isPng = buffer[0] === 0x89 && buffer[1] === 0x50
const isJpeg = buffer[0] === 0xFF && buffer[1] === 0xD8
if (!isPng && !isJpeg /* + webp check */) throw new Error('Invalid image')
const sanitized = await sharp(buffer).webp({ quality: 85 }).toBuffer()
```

**Warning signs:**
- Upload validation only checks `file.type` or file extension
- Uploaded files are served from `public/uploads/` without processing
- No `sharp` or equivalent image re-encoding in the upload pipeline

**Phase to address:** Security Hardening phase — must be done before any public launch.

---

### Pitfall 4: JWT Callback Queries the Database on Every Request for New/Unselected Users

**What goes wrong:**
The `needsRefresh` condition in `auth.config.ts` is `trigger === 'update' || !typedToken.subscriptionSelected || !typedToken.subscription`. New users who haven't selected a plan have `subscriptionSelected = false`, which means every single middleware invocation — including static file requests that Next.js routes through middleware — triggers two sequential Prisma queries. Under concurrent load this saturates the database connection pool, since Prisma's default pool is small and each request holds a connection for two queries.

**Why it happens:**
The condition was written defensively ("always have fresh subscription data"), but the `!typedToken.subscriptionSelected` branch fires continuously for new users rather than being a one-time catch-up. The intent was to refresh once; the result is refresh on every request.

**How to avoid:**
Change the refresh condition to fire only on `trigger === 'update'` (explicit refresh after a known state change, e.g., after plan selection or Stripe checkout). Remove the `!typedToken.subscription` auto-refresh branch entirely. Instead, populate subscription data once at sign-in (already done) and refresh it explicitly when the subscription state changes. For the `subscriptionSelected` redirect check, read from the DB only at the critical decision point (plan selection confirmation), not continuously.

**Warning signs:**
- Prisma query logs show `user.findUnique` + `subscription.findUnique` on every page load
- Database CPU spikes under modest load
- Slow TTFB (time to first byte) on all pages
- The `needsRefresh` condition includes any falsy field check, not just `trigger === 'update'`

**Phase to address:** Performance & Cleanup phase — address before load testing or public launch.

---

### Pitfall 5: PWA Offline Does Not Cover the Core Use Case — Barcode Display at the Register

**What goes wrong:**
Teams add a service worker, verify the app "loads offline," and ship the PWA. What they don't test: a user opens the app at a store checkout with no network, taps a card, and the barcode doesn't render because the card image (stored in `public/uploads/`) was not pre-cached and the bwip-js canvas render requires no network. The failure mode is a blank card view — exactly the moment the user needs it most.

The subtle issue: bwip-js renders barcodes client-side from the stored `barcodeValue` and `barcodeFormat` strings, so barcode generation itself works offline. What breaks is card images, the card list page if it makes any unfulfilled network request, and navigation to card detail pages for routes not previously visited via SPA navigation.

**Why it happens:**
Testing PWA offline is done in Chrome DevTools with a cached dashboard page. Developers assume "the page loaded" means "the use case works." The actual user flow (open installed PWA → cold start → no network → navigate to card) is not tested on a real device.

**How to avoid:**
Write the offline acceptance test first, before implementing the SW: install PWA, turn off network at OS level, cold-launch, navigate to a card detail page, verify barcode visible. Implement runtime caching for card images from `public/uploads/` using a Cache-First strategy. Ensure the card list and card detail routes are cached on first visit (navigation caching). Test on a real mobile device with Airplane Mode — DevTools offline simulation is not equivalent.

**Warning signs:**
- Offline test only done in DevTools network throttle
- Card images (`public/uploads/*.jpg`) not in runtime cache configuration
- Service worker scope doesn't include `/uploads/`
- No test for cold-start offline (not a previously-cached SPA navigation)

**Phase to address:** PWA Offline Support phase — test before considering the feature done.

---

### Pitfall 6: Feature Gates Checked Only Client-Side Allow Trivial Bypass

**What goes wrong:**
Feature gating is added as UI-only restrictions: hide the button, disable the input, show an upgrade prompt. A user opens DevTools, removes the `disabled` attribute or calls the Server Action directly via `fetch`. The actual data operation succeeds because the Server Action has no subscription check. Card creation, logo searches, or whatever the gated feature is proceeds for free users.

**Why it happens:**
The natural place to add gates is where the UI renders — it's fast, gives immediate feedback, and doesn't require changing server logic. Developers ship it and move on. The server-action authorization check feels redundant when the button is hidden.

**How to avoid:**
Every gated Server Action must re-verify subscription status by querying the DB at the top of the action, before performing any work. The UI restriction is a UX convenience, not a security control. Pattern:

```typescript
export async function createCard(prevState, formData) {
  const session = await auth()
  if (!session?.user?.id) redirect('/login')

  // DB-authoritative gate check — not JWT, not client state
  const sub = await prisma.subscription.findUnique({ where: { userId: session.user.id } })
  if (sub?.tier === 'FREE') {
    const count = await prisma.card.count({ where: { userId: session.user.id } })
    if (count >= FREE_CARD_LIMIT) return { error: 'Upgrade required' }
  }
  // ... rest of action
}
```

**Warning signs:**
- Feature gate logic only appears in React components, not in Server Actions
- Server Actions lack subscription tier checks at the top
- Gate condition reads from `session.user.subscription` (stale JWT) rather than fresh DB query

**Phase to address:** Stripe Payments & Feature Gating phase — gates must be server-authoritative by design.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Store subscription data in JWT | No DB query per request for tier | Stale data for active sessions after Stripe events; silent failures | Never for access-control decisions; acceptable for display-only hints |
| Read `File.type` for upload MIME validation | Fast, no dependencies | Bypassable by any attacker; malicious file upload | Never — magic bytes + re-encode required |
| Copy-paste barcode scanning logic between add/edit forms | Faster initial development | Bugs fixed in one place silently diverge; already happened (error message text differs) | Never — extract to shared hook before adding more features |
| Service worker with static cache name | Simple setup | Users run stale app versions after deployments | Never for production PWAs |
| Feature gates only in UI components | Visible immediately, low effort | Any user can bypass with DevTools or direct API call | Never for paid features |
| `onboardingComplete` dead field in JWT | Was needed at some point | DB query overhead on every JWT refresh for a no-op field | Delete it — pure cost, zero benefit |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| Stripe Webhooks | Assuming raw body is available via `request.json()` | Use `request.text()` to get raw body before `stripe.webhooks.constructEvent()` — the current code does this correctly; do not change it |
| Stripe Webhooks | Not handling idempotency — same event delivered twice updates subscription twice | Wrap DB updates in upsert operations; the current `syncSubscriptionFromStripe` should be idempotent |
| Stripe Webhooks | Missing `customer.subscription.updated` handling means plan upgrades/downgrades not synced | Current handler covers `created`, `updated`, `deleted` — correct |
| NextAuth v5 beta | Passing `session` prop to `SessionProvider` makes the session static on the client; token rotation stops working | Do not pass the `session` prop statically; let NextAuth manage it |
| NextAuth v5 beta | JWT and session callbacks interact differently than v4; `auth()` on the server returns jwt callback data, not session callback data in some versions | Test all auth data access paths after any NextAuth beta version bump |
| @zxing/browser in React 19 Strict Mode | `useEffect` double-invocation starts two scanner instances; cleanup (`controls.stop()`) not called in effect return | Always return a cleanup function that calls `controls.stop()` from any `useEffect` that starts the scanner |
| Prisma + account deletion | Forgetting `onDelete: Cascade` on relations means `prisma.user.delete()` throws a foreign key violation | Add `onDelete: Cascade` to all User-owned relations (Card, Subscription, BrandLogo) and test with a migration before exposing the delete endpoint |
| Next.js static file serving | Files in `public/` are served without auth checks; uploaded images at `public/uploads/` are publicly accessible by URL | Acceptable for card images (no PII in images), but do not store sensitive files in `public/` |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| JWT callback DB queries on every request (current issue) | Slow TTFB, high DB CPU, connection pool exhaustion | Refresh only on `trigger === 'update'`, not on field absence checks | Under any concurrent load; already observable with 1 user on subscribe page |
| `getInitialTheme()` calls `auth()` + DB query on every root layout render | Every page — including public homepage — is slow | Move theme preference to a cookie; read cookie in layout without any auth call | Immediately with any traffic; adds ~20ms+ per request in Docker |
| Dashboard fetches all cards without pagination | Page load grows linearly with card count; 100 cards = 100x data over wire | Cursor-based pagination from the start; or virtual scroll if keeping flat fetch | Noticeable at 50+ cards; painful at 200+ |
| Logo search fires external API calls on every search without debouncing at server | Clearbit/logo.dev rate limits hit; slow search responses; cost from API calls | Client-side debounce (300ms) + `Promise.all` for parallel Clearbit + logo.dev fetches | At any usage; currently fires on modal open which is immediate |
| Prisma default connection pool (10 connections) with DB queries in middleware | Under load, requests queue waiting for a connection | Reduce JWT refresh DB queries; connection pool is adequate for single-server self-hosted | At ~20+ concurrent users |

---

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| No rate limiting on `/register` and `/login` server actions | Brute-force password attacks; account enumeration via timing; bot registration | Add rate limiting in middleware keyed by IP — 5 attempts per 15 minutes for auth, 3 per hour for registration. Use `@upstash/ratelimit` with an in-memory store for self-hosted (no Redis required for single instance) |
| `STRIPE_MONTHLY_PRICE_ID!` non-null assertion in API routes | If env var missing, `undefined` passed to Stripe; Stripe API error leaks in 500 response | Validate all required env vars at startup (in a `validateEnv()` function called from `next.config.mjs`) and fail hard during build/start |
| Uploaded files served from `public/uploads/` without content-type enforcement | Browser renders HTML/SVG files uploaded with wrong extension; XSS via uploaded content | Serve uploads through a Next.js route handler that sets `Content-Type: image/webp` and `Content-Disposition: attachment` headers, or process all uploads through `sharp` to guarantee output is valid image bytes |
| No MIME validation on current uploads | Any file type can be stored on the server | Magic bytes validation + `sharp` re-encode (see Pitfall 3) |
| `dangerouslySetInnerHTML` for SW registration script | Low risk currently (static string), but fragile | Replace with `<Script strategy="afterInteractive">` from `next/script`; eliminates the risk entirely |
| Barcode format stored as free-text passed to bwip-js | Invalid format string causes unhandled exception silently swallowed | Validate `barcodeFormat` against a Zod enum of allowed bwip-js bcid values before storing; reject unknown formats at save time |

---

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Blank barcode area on render failure (current bug) | User at store register has no card to scan; no indication of what went wrong | Show a visible error state with the raw barcode value as text so a cashier can type it manually |
| "Skip for now" infinite redirect loop (current bug) | User clicks skip, gets redirected back to subscribe forever; effectively locked out | "Skip for now" must be a Server Action that sets `subscriptionSelected = true` and then redirects; not a plain `<Link>` |
| Free tier not obvious on subscription page (current issue) | Users confused about whether they need to pay; churn before getting started | Make FREE the pre-selected default with a clear "Start for free" CTA; paid plans are opt-in upgrades |
| Offline state not communicated to user | App appears broken when network drops; user doesn't know cards are available offline | Show a persistent offline indicator banner; explicitly tell users "Your cards are available offline" |
| PWA install prompt not shown on first meaningful use | Users don't discover the installable PWA; miss offline capability | Trigger install prompt after first card is added (user has demonstrated value) |

---

## "Looks Done But Isn't" Checklist

- [ ] **PWA Offline:** Service worker is registered and manifest exists — verify cold-start offline works on a real mobile device with Airplane Mode, not just DevTools
- [ ] **Stripe Payments:** Checkout flow completes and webhook fires — verify that the user's session reflects the new subscription tier without requiring re-login
- [ ] **Feature Gating:** Gate logic is in the UI — verify that calling the Server Action directly (no UI) via `fetch()` is also blocked for free users
- [ ] **Account Deletion:** Delete button exists and hits a Server Action — verify that all uploaded files in `public/uploads/` are deleted from disk, not just the DB record
- [ ] **File Upload Security:** MIME type is checked — verify by uploading a `.html` file with `Content-Type: image/jpeg` and confirming it is rejected or re-encoded
- [ ] **Subscribe Page "Skip" Fix:** Skip button navigates away — verify that clicking skip sets `subscriptionSelected = true` so users are not redirected back on next request
- [ ] **Image Cleanup on Delete/Update:** Card delete removes DB record — verify the file at `public/uploads/{uuid}` is also gone from disk
- [ ] **Rate Limiting:** Login route has rate limiting — verify 6 rapid attempts return 429, not 200 or 401

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Stale JWT subscription state shipped to production | MEDIUM | Add a server-side DB check wrapper around all feature gates; deploy hotfix; users who paid and are stuck can re-login as workaround |
| Service worker serving stale app version | HIGH | Requires shipping a new SW that unregisters itself, waiting for affected users to load the page once, then re-deploying; no forced upgrade path |
| Malicious file uploaded via missing MIME validation | HIGH | Audit `public/uploads/`; delete suspect files; add sharp processing; rotate any secrets if server was compromised |
| JWT cookie size overflow due to subscription payload growth | MEDIUM | Remove subscription data from JWT; switch to DB-authoritative checks at runtime; users need to re-login to get new cookie |
| Feature gate bypass exploited | HIGH | Remove gated content from DB for affected users; add server-side checks; audit logs for abuse |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Subscription state in JWT used for access control | Stripe Payments & Feature Gating | Server Actions for gated features must show DB query for subscription tier, not JWT read |
| Service worker caches stale build artifacts | PWA Offline Support | Deploy a new build, verify installed PWA updates within one session |
| File upload MIME bypass | Security Hardening | Upload a renamed HTML file; confirm it is rejected or re-encoded to valid image bytes |
| JWT callback DB queries on every request | Performance & Cleanup | Check Prisma query logs; confirm no DB queries fire on static page loads |
| Core use case (barcode at register) broken offline | PWA Offline Support | Cold-start on Airplane Mode → navigate to card detail → barcode visible |
| Client-only feature gates | Stripe Payments & Feature Gating | Call Server Action directly via fetch without UI; confirm 403/error for free-tier-exceeding action |
| "Skip for now" infinite redirect | Bug Fix phase | Click skip; navigate away; navigate back; confirm no redirect loop |
| File orphans on card delete/update | Bug Fix phase | Delete a card with an image; confirm file is removed from `public/uploads/` |
| No rate limiting on auth | Security Hardening | Fire 6 rapid login requests; confirm 429 response on the 6th |
| Account deletion missing cascade | Account Management phase | Delete user account; confirm `Card`, `Subscription`, and image files are all gone |

---

## Sources

- Codebase analysis: `/home/autopcap/storecard/.planning/codebase/CONCERNS.md` — direct audit of known bugs, security issues, and fragile areas (HIGH confidence)
- Live code review: `auth.config.ts` — JWT callback refresh condition confirmed by reading the file (HIGH confidence)
- Live code review: `app/api/webhooks/stripe/route.ts` — webhook handler confirmed correct but session sync gap identified (HIGH confidence)
- NextAuth v5 JWT issues: [JWT Token Refresh Issue in Auth.js v5](https://medium.com/@elham1378basir/jwt-token-refresh-issue-in-auth-js-74ca5185476c), [NextAuth Session Management 2025](https://clerk.com/articles/nextjs-session-management-solving-nextauth-persistence-issues) (MEDIUM confidence)
- NextAuth cookie size limit: [NextAuth cookie chunking issue #2145](https://github.com/nextauthjs/next-auth/issues/2145), [Auth.js Session Strategies](https://authjs.dev/concepts/session-strategies) (HIGH confidence)
- Next.js PWA service worker pitfalls: [Building Native-Like Offline Experience in Next.js PWAs](https://www.getfishtank.com/insights/building-native-like-offline-experience-in-nextjs-pwas), [Next.js 16 PWA offline support — LogRocket](https://blog.logrocket.com/nextjs-16-pwa-offline-support/) (MEDIUM confidence)
- Service worker / App Router conflicts: [Building an Offline-First Next.js 15 App](https://github.com/vercel/next.js/discussions/82498) (MEDIUM confidence)
- Stripe webhook best practices: [Stripe webhooks documentation](https://docs.stripe.com/billing/subscriptions/webhooks), [Stripe + Next.js 15 guide](https://www.pedroalonso.net/blog/stripe-nextjs-complete-guide-2025/) (HIGH confidence)
- File upload security: [File upload security in Next.js](https://moldstud.com/articles/p-handling-file-uploads-in-nextjs-best-practices-and-security-considerations) (MEDIUM confidence)
- Rate limiting Next.js: [Rate-limiting Server Actions in Next.js](https://nextjsweekly.com/blog/rate-limiting-server-actions), [Next.js security guide 2025](https://www.turbostarter.dev/blog/complete-nextjs-security-guide-2025-authentication-api-protection-and-best-practices) (MEDIUM confidence)
- GDPR / cascade delete Prisma: [Deleting User Account and All Related Data](https://www.answeroverflow.com/m/1288414225005547592), [Prisma cascade delete discussion](https://github.com/prisma/prisma/discussions/2149) (MEDIUM confidence)
- ZXing React 19 Strict Mode: [react-zxing npm](https://www.npmjs.com/package/react-zxing), [ZXing camera stop issue](https://github.com/zxing-js/browser/issues/19) (MEDIUM confidence — no direct React 19 specific report found; based on well-understood class of double-invocation problems)

---
*Pitfalls research for: StoreCard loyalty PWA — brownfield production upgrade*
*Researched: 2026-02-28*
