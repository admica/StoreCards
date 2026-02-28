# Phase 1: Bug Fixes and Security - Context

**Gathered:** 2026-02-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Close live bugs and security gaps before any public user signs up. The application must have reliable auth flow, secure file uploads, validated barcode formats, rate-limited auth endpoints, deduplicated code, and no dead code. This phase does NOT change the subscribe page UX beyond fixing the broken skip flow, does NOT add toast notifications or loading states (Phase 2), and does NOT change theme storage (Phase 3).

</domain>

<decisions>
## Implementation Decisions

### Rate Limiting
- Apply to both login and registration endpoints (same 5 attempts per IP per 15 min window)
- Enforce at the middleware level in `middleware.ts` — block before request reaches Server Actions or NextAuth
- Show specific countdown: "Too many attempts. Try again in X minutes."
- Auth endpoints only — logo search is behind auth and will get client-side debounce in Phase 2
- Use in-memory lru-cache as specified in requirements (single-container deployment)

### Image Upload Validation
- Accept JPG, PNG, and WebP formats only — validated via magic bytes (not file.type header)
- Re-encode all uploads to WebP via sharp for storage (strips metadata, reduces file size)
- Resize to max 800px on longest dimension during re-encode
- Stored files change from `.jpg` to `.webp` extension
- Rejection shown as inline form error: "Only JPG, PNG, and WebP images are accepted."

### Dead Code Removal
- `onboardingComplete`: Remove completely — drop from Prisma schema (migration), remove from auth callbacks, remove from type augmentation
- `extractColorsFromUrl`: Delete the stub function entirely — client-side colorthief covers the use case
- Empty email verification directories: Delete all (`send-verification-code/`, `verify-email/`, `test-email/`, `app/verify-email/`)
- `backfill-colors` API route: Delete — it depends on the stub being removed and is unauthenticated

### Skip Subscription Flow (BUG-01)
- Replace both "Choose Free" and "Skip for now" with a single "Continue with Free" button
- Button calls a server action that: creates a FREE subscription record in DB + sets `subscriptionSelected = true`
- Every user gets a Subscription row from day one (simplifies Phase 6 feature gating)
- Redirect straight to dashboard after — no confirmation step, no welcome message
- Leave paid plan display as-is ("Coming Soon") — Phase 4 (SUB-04) handles the subscribe page UX redesign

### Claude's Discretion
- Exact lru-cache configuration (max entries, TTL implementation)
- Sharp pipeline details (quality level, exact resize behavior for non-square images)
- Barcode format enum validation — which bwip-js format strings to allow
- Order of code quality improvements (useFormState migration, dedup, dead code)
- How to structure the shared `useBarcodeScanner` hook and `cacheBrandLogo` helper

</decisions>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches for the implementation details. Key constraint: all changes must pass `npm run build` and `npm run lint` since there are zero tests.

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `lib/prisma.ts`: Singleton Prisma client — all DB operations go through this
- `app/lib/actions.ts`: Single server actions file — all mutations consolidated here
- `middleware.ts`: Already exists with NextAuth authorized callback — rate limiting hooks in here
- `auth.config.ts`: JWT/session callbacks that will need `onboardingComplete` stripped

### Established Patterns
- Server Actions return `string | undefined` for errors (createCard, updateCard) or `{ error: string }` objects (selectPlan)
- Image uploads use `randomUUID()` filenames written to `public/uploads/` via `fs.writeFile`
- Zod validation used inline at point of use (not shared schemas)
- Best-effort operations (logo caching) swallow errors silently with `// best-effort` comments
- `useFormState` from `react-dom` used in add-card-form, edit-form, subscribe page (migrating to `useActionState`)

### Integration Points
- `middleware.ts` — rate limit check added before NextAuth authorized callback
- `app/lib/actions.ts` createCard/updateCard — sharp pipeline inserted into image upload flow
- `app/lib/actions.ts` selectPlan — reworked to be the single "Continue with Free" handler
- `prisma/schema.prisma` — migration to drop `onboardingComplete` field
- `app/subscribe/page.tsx` — UI change to single "Continue with Free" button

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 01-bug-fixes-and-security*
*Context gathered: 2026-02-28*
