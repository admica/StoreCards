# Codebase Concerns

**Analysis Date:** 2026-02-28

## Tech Debt

**Massive Code Duplication in Barcode Scanning:**
- Issue: The entire barcode scanning workflow (3-method fallback with rotation, EXIF handling) is copy-pasted verbatim between `add-card-form.tsx` and `edit-form.tsx`. The `mapBarcodeFormat` function is also duplicated in both files.
- Files: `app/add/add-card-form.tsx` (lines 62-149), `app/card/[id]/edit/edit-form.tsx` (lines 66-151)
- Impact: Any bug fix or improvement must be applied in two places. This has already diverged slightly (error message text differs between the two).
- Fix approach: Extract scanning logic into a shared `useBarcodeScanner` hook in `app/lib/hooks/` or a shared `BarcodeScanner` component.

**Logo Caching Logic Duplicated in createCard/updateCard:**
- Issue: The `brandLogo` upsert block (retailer name normalization, cache write) is copy-pasted between `createCard` and `updateCard` in `actions.ts`.
- Files: `app/lib/actions.ts` (lines 159-183, lines 267-291)
- Impact: Normalization rules can diverge; bugs must be fixed twice.
- Fix approach: Extract a `cacheBrandLogo(retailer, logo, colorLight, colorDark)` helper function.

**`extractColorsFromUrl` is a Stub:**
- Issue: `extractColorsFromUrl` in `app/lib/color-utils.ts` is a no-op that logs a warning. It accepts a parameter, immediately voids it, and returns `null`. The function signature promises server-side color extraction that was never implemented.
- Files: `app/lib/color-utils.ts` (lines 196-204)
- Impact: Any server-side color extraction call silently returns nothing.
- Fix approach: Either implement it with `node-canvas` or remove it and throw an error to fail loudly.

**`onboardingComplete` Field is Unused:**
- Issue: The `User` model has an `onboardingComplete` boolean field that is tracked through the auth JWT pipeline but never used to make any routing or access decisions. The middleware only checks `subscriptionSelected`, not `onboardingComplete`.
- Files: `prisma/schema.prisma` (line 37), `auth.config.ts` (lines 16, 33, 56, 90, 97), `auth.ts` (line 33)
- Impact: Dead code pollutes the token and adds unnecessary DB queries on every auth refresh.
- Fix approach: Remove from schema (requires migration), auth config, and types, or implement an actual onboarding flow that uses it.

**Dead Email Verification Code:**
- Issue: Directory structure shows `app/api/auth/send-verification-code/`, `app/api/auth/verify-email/`, `app/api/test-email/`, and `app/verify-email/` directories exist but contain no route files. These are empty dead directories from an abandoned email verification feature.
- Files: `app/api/auth/send-verification-code/`, `app/api/auth/verify-email/`, `app/api/test-email/`, `app/verify-email/`
- Impact: Confusing codebase navigation; Prisma schema still has verification-related migrations.
- Fix approach: Remove empty directories, clean up related schema fields if present.

**`useFormState` is Deprecated:**
- Issue: `useFormState` from `react-dom` is deprecated in React 19. Both forms use the old API.
- Files: `app/add/add-card-form.tsx` (line 16), `app/card/[id]/edit/edit-form.tsx` (line 28), `app/subscribe/page.tsx` (line 27)
- Impact: Will generate deprecation warnings; `useActionState` from `react` is the replacement.
- Fix approach: Replace `useFormState` from `react-dom` with `useActionState` from `react`.

**Stripe Singleton May Reuse Stale Instance:**
- Issue: `lib/stripe.ts` uses a module-level singleton `_stripe`. If `STRIPE_SECRET_KEY` changes between deployments (e.g., environment update without restart), the stale instance persists.
- Files: `lib/stripe.ts` (lines 14-20)
- Impact: Low risk in practice but could cause authentication failures after key rotation without restart.
- Fix approach: Acceptable as-is for self-hosted, but consider factory function pattern without caching.

## Known Bugs

**Uploaded Images Not Deleted When Card is Deleted:**
- Symptoms: Calling `deleteCard` removes the DB record but the uploaded image file at `public/uploads/{uuid}.jpg` remains on disk permanently.
- Files: `app/lib/actions.ts` (lines 189-203)
- Trigger: Delete any card that has an uploaded image.
- Workaround: Manual cleanup of `public/uploads/` directory.

**Old Image Not Cleaned Up on Card Update:**
- Symptoms: When a card image is replaced via `updateCard`, the old image file at `public/uploads/` is never deleted.
- Files: `app/lib/actions.ts` (lines 235-251)
- Trigger: Edit a card and upload a new image when one already exists.
- Workaround: None; orphaned files accumulate silently.

**Subscribe Page "Skip for now" Link Does Not Set `subscriptionSelected`:**
- Symptoms: The "Skip for now" link on `/subscribe` redirects to `/dashboard` as a plain `<Link>`. The middleware `authorized` callback checks `hasSelectedPlan = !!auth?.user?.subscriptionSelected`. If a user clicks "Skip", `subscriptionSelected` remains `false` and they will be redirected back to `/subscribe` on every request.
- Files: `app/subscribe/page.tsx` (line 48), `auth.config.ts` (lines 129-138)
- Trigger: Click "Skip for now" on the subscription page.
- Workaround: User must click "Choose Free" to actually proceed.

**Barcode Component Silently Swallows Render Errors:**
- Symptoms: If `bwip-js` fails to render (invalid format string, bad value), the canvas renders nothing and the error is only logged to console. Users see a blank barcode area.
- Files: `app/components/Barcode.tsx` (lines 20-23)
- Trigger: A card with an unsupported `barcodeFormat` value or malformed `barcodeValue`.
- Workaround: None; user has no indication of failure.

## Security Considerations

**No File Type Validation on Image Uploads:**
- Risk: File uploads in `createCard` and `updateCard` only check file size (5MB limit), not MIME type or extension. An attacker could upload a `.php`, `.html`, or `.svg` file with a malicious `image/*` content type. Files are served directly from `public/uploads/` as static assets.
- Files: `app/lib/actions.ts` (lines 125-143, 233-251)
- Current mitigation: Server Actions require authentication; path traversal is avoided via `randomUUID()` filenames.
- Recommendations: Validate MIME type using the actual file buffer (not the `File.type` header). Restrict extensions to `['.jpg', '.jpeg', '.png', '.webp', '.gif']`. Consider processing images through `sharp` to sanitize content.

**STRIPE_MONTHLY_PRICE_ID and STRIPE_YEARLY_PRICE_ID Use Non-Null Assertions:**
- Risk: `process.env.STRIPE_MONTHLY_PRICE_ID!` and `process.env.STRIPE_YEARLY_PRICE_ID!` in checkout/update routes will silently pass `undefined` to Stripe if env vars are not set, leading to a Stripe API error that leaks internal error details in the 500 response.
- Files: `app/api/create-checkout-session/route.ts` (lines 20-21), `app/api/subscription/update/route.ts` (lines 21-22)
- Current mitigation: Error caught and returned as 500.
- Recommendations: Add explicit env var validation at startup or in each route before using these values.

**No Rate Limiting on Auth or Registration Endpoints:**
- Risk: The registration endpoint (`register` server action) and login endpoint have no rate limiting. Brute-force password attacks and account enumeration (different error messages for wrong email vs. wrong password) are possible. The `searchLogos` server action makes external API calls on every keystroke without debouncing at the server level.
- Files: `app/lib/actions.ts` (lines 27-96), `auth.ts` (lines 16-41)
- Current mitigation: None detected.
- Recommendations: Add rate limiting middleware (e.g., `upstash/ratelimit` or nginx-level) for auth routes. The auth error messages are appropriately generic for CredentialsSignin.

**No CSRF Protection Verification Beyond NextAuth Defaults:**
- Risk: Server Actions use Next.js's built-in CSRF protection via origin header checking. Non-Server Action API routes (`/api/subscription/*`, `/api/create-checkout-session`) rely on session-based auth only.
- Files: All routes under `app/api/`
- Current mitigation: Auth session check on all routes provides implicit protection.
- Recommendations: Acceptable for current scope.

**`dangerouslySetInnerHTML` in Root Layout:**
- Risk: A hardcoded service worker registration script is injected via `dangerouslySetInnerHTML` in the root layout. The content is static and not user-controlled, so XSS risk is minimal.
- Files: `app/layout.tsx` (lines 57-61)
- Current mitigation: Content is a static string literal, not user input.
- Recommendations: Low priority; could be replaced with a `<Script>` component from `next/script`.

## Performance Bottlenecks

**JWT Callback Makes Multiple DB Queries on Every Request:**
- Problem: The `jwt` callback in `auth.config.ts` queries the database on nearly every token refresh. The condition `!typedToken.subscriptionSelected || !typedToken.subscription` means any session where `subscriptionSelected` is falsy (including new users on `/subscribe`) triggers two sequential Prisma queries (`user` + `subscription`) on every middleware invocation.
- Files: `auth.config.ts` (lines 83-123)
- Cause: Over-eager refresh condition combined with storing subscription data in the JWT.
- Improvement path: Add explicit cache/TTL for subscription data in the token; only refresh on `trigger === 'update'` after a subscription change.

**Dashboard Loads All Cards Without Pagination:**
- Problem: `prisma.card.findMany` in the dashboard fetches all cards for the user with no `take`/`skip` limit. A user with 100+ cards loads them all on every dashboard render.
- Files: `app/dashboard/page.tsx` (lines 51-60)
- Cause: No pagination implemented.
- Improvement path: Add cursor-based pagination or implement virtual scrolling on the client.

**`getInitialTheme` Adds Auth + DB Query to Every Root Layout Render:**
- Problem: The root layout calls `getInitialTheme()` on every page load, which calls `auth()` and potentially `prisma.user.findUnique`. This adds latency to every page including public routes.
- Files: `app/layout.tsx` (lines 31-45)
- Cause: Dark mode preference stored in DB instead of a cookie.
- Improvement path: Store dark mode preference in a cookie so it can be read without a DB query; fall back to DB for first load.

**Logo Search Triggers Clearbit + logo.dev API Calls Per Search:**
- Problem: The `searchLogos` server action calls both Clearbit and logo.dev APIs synchronously in sequence on every search. There is no debouncing — the logo picker auto-searches when the modal opens.
- Files: `app/lib/actions.ts` (lines 389-481), `components/logo-picker.tsx` (lines 87-93)
- Cause: Sequential external API calls with no parallelization (`Promise.all` not used).
- Improvement path: Run Clearbit and logo.dev fetches in parallel with `Promise.all`; add client-side debounce before triggering search action.

## Fragile Areas

**Auth Token Refresh Logic:**
- Files: `auth.config.ts` (lines 43-125)
- Why fragile: The `needsRefresh` condition (`trigger === 'update' || !typedToken.subscriptionSelected || !typedToken.subscription`) runs database queries inside every JWT callback invocation during the session lifecycle. Logic is complex — initial sign-in populates the token, then a separate refresh block re-populates it. Duplicate population paths can cause inconsistencies.
- Safe modification: Any change to session data shape requires updating 4 separate places: the `authorize` return in `auth.ts`, the JWT `user` block, the JWT `needsRefresh` block, and the `session` callback.
- Test coverage: None.

**Subscription State Synchronization:**
- Files: `lib/stripe.ts`, `app/api/webhooks/stripe/route.ts`
- Why fragile: Subscription state lives in two places: the PostgreSQL `Subscription` table and the user's JWT token. The JWT only refreshes on `trigger === 'update'` or when certain fields are missing. After a webhook updates subscription state in the DB, the user's active session won't reflect the new state until their next login or token refresh.
- Safe modification: After any subscription state change, force a session update using `unstable_update` from NextAuth.
- Test coverage: None.

**Image Upload Uses Filesystem Path Relative to `process.cwd()`:**
- Files: `app/lib/actions.ts` (lines 135, 243)
- Why fragile: Image uploads go to `public/uploads/` resolved via `process.cwd()`. In Docker/standalone mode, `process.cwd()` may not be the project root. Additionally, `public/uploads/` is served as a static asset by Next.js, so this directory must persist across deployments.
- Safe modification: Verify the Docker `WORKDIR` matches where Next.js expects `public/`. Uploaded images will be lost on container restart without a volume mount.
- Test coverage: None.

**Barcode Format Strings Are Unvalidated Free Text:**
- Files: `app/lib/actions.ts` (line 115), `prisma/schema.prisma` (line 62)
- Why fragile: `barcodeFormat` is stored as a free-text `String?` in the database. The `Barcode` component passes it directly to `bwip-js` as the `bcid` parameter. An invalid format string causes bwip-js to throw, which is silently swallowed.
- Safe modification: Validate `barcodeFormat` against the allowed enum values in the server action before storing.
- Test coverage: None.

## Scaling Limits

**Local Filesystem Image Storage:**
- Current capacity: Limited by server disk space.
- Limit: Does not scale horizontally — images are stored at `public/uploads/` on the single server. Multiple server instances would not share uploaded files.
- Scaling path: Migrate to object storage (S3, Cloudflare R2) before any horizontal scaling or multi-instance deployment.

**PostgreSQL Single Instance:**
- Current capacity: Single local PostgreSQL via Docker Compose.
- Limit: No connection pooling configured (Prisma default pool). No read replicas. Acceptable for single-user/small deployment.
- Scaling path: Add PgBouncer for connection pooling if concurrent users increase.

## Dependencies at Risk

**`next-auth` v5 Beta:**
- Risk: `next-auth@^5.0.0-beta.30` is a beta release used in production. Breaking changes can land in minor/patch versions of beta releases.
- Impact: Auth system, session management, and JWT handling could break on dependency update.
- Migration plan: Monitor `next-auth` v5 stable release; pin to a specific beta version to avoid unexpected updates.

**`@zxing/browser` 0.1.5 + `react-zxing` 1.1.3:**
- Risk: `@zxing/browser` 0.1.5 is a pre-1.0 release. `react-zxing` has not been updated in over a year and has known issues with React 19 strict mode double-invocation.
- Impact: Barcode scanning — the core feature — depends on these unmaintained wrappers.
- Migration plan: Evaluate `@zxing/browser` 0.3.x or the `zxing-wasm` alternative if scanning issues arise.

## Missing Critical Features

**No Image Cleanup on Card Delete/Update:**
- Problem: Uploaded files in `public/uploads/` grow indefinitely with no automatic cleanup.
- Blocks: Disk space management on self-hosted deployment.

**No Subscription Enforcement:**
- Problem: The app currently has no code that enforces subscription tier differences. All users on FREE tier have identical access to all features. The MONTHLY/YEARLY tiers are built in Stripe and Prisma but no feature gates exist.
- Blocks: Monetization — paid tiers cannot be launched without implementing feature gating.

**No Account Deletion:**
- Problem: The settings page only offers sign out. There is no way for a user to delete their account or data, which may be required for GDPR compliance.
- Blocks: Privacy compliance for users in regulated regions.

## Test Coverage Gaps

**Zero Test Coverage:**
- What's not tested: The entire codebase has no test files (confirmed: no `*.test.*` or `*.spec.*` files found).
- Files: All files under `app/`, `lib/`, `components/`
- Risk: Any regression in auth flow, card CRUD, image upload, Stripe webhook handling, or barcode scanning would go undetected until user reports.
- Priority: High — particularly for `app/lib/actions.ts` (business logic), `auth.config.ts` (auth/redirect logic), and `lib/stripe.ts` (payment processing).

---

*Concerns audit: 2026-02-28*
