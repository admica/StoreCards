# Phase 1: Bug Fixes and Security - Research

**Researched:** 2026-02-28
**Domain:** Next.js 16 App Router security hardening, image upload validation, rate limiting, React 19 hook migration, dead code removal
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Rate Limiting**
- Apply to both login and registration endpoints (same 5 attempts per IP per 15 min window)
- Enforce at the middleware level in `middleware.ts` — block before request reaches Server Actions or NextAuth
- Show specific countdown: "Too many attempts. Try again in X minutes."
- Auth endpoints only — logo search is behind auth and will get client-side debounce in Phase 2
- Use in-memory lru-cache as specified in requirements (single-container deployment)

**Image Upload Validation**
- Accept JPG, PNG, and WebP formats only — validated via magic bytes (not file.type header)
- Re-encode all uploads to WebP via sharp for storage (strips metadata, reduces file size)
- Resize to max 800px on longest dimension during re-encode
- Stored files change from `.jpg` to `.webp` extension
- Rejection shown as inline form error: "Only JPG, PNG, and WebP images are accepted."

**Dead Code Removal**
- `onboardingComplete`: Remove completely — drop from Prisma schema (migration), remove from auth callbacks, remove from type augmentation
- `extractColorsFromUrl`: Delete the stub function entirely — client-side colorthief covers the use case
- Empty email verification directories: Delete all (`send-verification-code/`, `verify-email/`, `test-email/`, `app/verify-email/`)
- `backfill-colors` API route: Delete — it depends on the stub being removed and is unauthenticated

**Skip Subscription Flow (BUG-01)**
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

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope.
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| BUG-01 | "Skip for now" on subscribe page sets `subscriptionSelected = true` and redirects to dashboard | `selectPlan` action rework + authorized callback analysis |
| BUG-02 | Uploaded images deleted from disk when card is deleted (`fs.unlink`) | `deleteCard` action currently missing unlink call |
| BUG-03 | Old image file cleaned up when card image is replaced via update | `updateCard` action currently retains old path without unlinking |
| SEC-01 | File uploads validated server-side via magic bytes + sharp re-encode | Sharp `metadata()` auto-detects format from buffer; re-encode sanitizes content |
| SEC-02 | Rate limiting on login/register endpoints (5 attempts per IP, 15 min, lru-cache) | `proxy.ts` (Node.js runtime) supports lru-cache; middleware.ts is Edge-only |
| SEC-03 | Barcode format validated against allowed enum values before storing in DB | Allowlist of 8 bwip-js format strings matches existing UI options |
| QUAL-01 | Barcode scanning logic extracted into shared `useBarcodeScanner` hook | `add-card-form.tsx` and `edit-form.tsx` share identical scanning logic ~150 lines |
| QUAL-02 | Brand logo caching extracted into `cacheBrandLogo` helper | `createCard` and `updateCard` share identical logo caching block ~20 lines |
| QUAL-03 | Dead code removed: `onboardingComplete`, empty email dirs, `extractColorsFromUrl` | 3 empty dirs confirmed; `onboardingComplete` in schema + 3 auth files |
| QUAL-04 | `useFormState` migrated to `useActionState` across all forms | React 19: import changes from `react-dom` to `react`; returns `isPending` as 3rd value |
| QUAL-05 | `dangerouslySetInnerHTML` SW script replaced with `next/script` component | `afterInteractive` + `id` prop required; import from `next/script` |
| PERF-03 | Logo search runs Clearbit + logo.dev in parallel via `Promise.all` | Currently sequential await calls; trivial to parallelize |
</phase_requirements>

---

## Summary

Phase 1 addresses security and correctness gaps before any public users sign up. The work splits into four clusters: (1) fixing the subscribe redirect loop by reworking `selectPlan`, (2) closing file system leak bugs in `deleteCard`/`updateCard`, (3) hardening uploads with sharp magic-byte validation + WebP re-encoding, and (4) adding rate limiting to auth endpoints. Code quality work (hook extraction, dead code removal, React 19 migration) runs alongside and is low-risk since the project has no automated tests — all changes must validate against `npm run build` and `npm run lint`.

**Critical platform finding:** The project runs Next.js 16.0.8 where `middleware.ts` is deprecated in favor of `proxy.ts`. The key implication is that `proxy.ts` runs on the **Node.js runtime** (not Edge), meaning `lru-cache` can be used directly. The user's constraint to "enforce at the middleware level" maps to `proxy.ts` in Next.js 16 — this is the correct implementation path, not the old `middleware.ts`.

**Primary recommendation:** Rename `middleware.ts` to `proxy.ts`, implement rate limiting with `lru-cache` directly in the proxy function (Node.js runtime), use sharp's `metadata()` for format validation before re-encoding to WebP, and migrate `useFormState` imports from `react-dom` to `useActionState` from `react`.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `sharp` | latest (^0.33) | Image processing: magic-byte validation via metadata(), WebP re-encode, resize | Industry-standard libvips wrapper; strips EXIF/metadata as security bonus; native Node.js performance |
| `lru-cache` | latest (^11) | In-memory rate limit counter with TTL per IP | Zero-dependency, typed, built-in TTL support; matches REQUIREMENTS.md spec |
| `next/script` | built-in | Replace `dangerouslySetInnerHTML` for service worker registration | Next.js built-in; CSP-safe; proper script loading lifecycle |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `fs/promises` (Node built-in) | - | `unlink()` for orphaned file cleanup | Already used in actions.ts for `writeFile`; just add unlink calls |
| `path` (Node built-in) | - | Construct filesystem paths for uploaded files | Already imported in actions.ts |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `lru-cache` | `@upstash/ratelimit` + Redis | Redis adds infrastructure complexity; single-container deployment doesn't need distributed rate limiting |
| `sharp` metadata() | Manual buffer magic bytes | Sharp's detection is more accurate (deep decode-level, not just header sniff); also re-encodes in one pass |
| `proxy.ts` | Keep `middleware.ts` | `middleware.ts` is deprecated in Next.js 16; Edge runtime blocks `lru-cache` |

**Installation:**
```bash
npm install sharp
# lru-cache is likely already a transitive dep; verify:
npm ls lru-cache
# If missing:
npm install lru-cache
```

---

## Architecture Patterns

### Recommended Project Structure

After Phase 1, new files introduced:

```
app/
├── lib/
│   ├── actions.ts          # Updated: sharp pipeline, unlink, selectPlan rework, parallel logos
│   └── rate-limit.ts       # NEW: lru-cache singleton + isRateLimited(ip) helper
├── hooks/                  # NEW directory
│   └── useBarcodeScanner.ts # NEW: extracted shared scanning hook
proxy.ts                    # RENAMED from middleware.ts; rate limit check here
```

### Pattern 1: proxy.ts Rate Limiting (Node.js Runtime)

**What:** Import `lru-cache` in `proxy.ts` (formerly `middleware.ts`) to count requests per IP. Return 429 before NextAuth processes the request.

**When to use:** Auth endpoints only (`/api/auth/callback/credentials`, `/api/auth/signin`). The proxy intercepts all matching routes before Server Actions run.

**Why proxy.ts not middleware.ts:** Next.js 16 deprecated `middleware.ts`. The new `proxy.ts` runs on Node.js runtime, enabling direct use of `lru-cache`. The `middleware.ts` file (Edge runtime) cannot maintain shared in-memory state between requests reliably.

```typescript
// Source: Next.js 16 blog + lru-cache npm docs
// proxy.ts (replaces middleware.ts)
import { NextRequest, NextResponse } from 'next/server'
import { LRUCache } from 'lru-cache'

const rateLimitCache = new LRUCache<string, number>({
  max: 500,           // track up to 500 unique IPs
  ttl: 1000 * 60 * 15, // 15-minute window per CONTEXT.md
})

const RATE_LIMIT = 5  // 5 attempts per 15 min per CONTEXT.md

function getRemainingTime(ip: string): number {
  // lru-cache v10+ exposes getRemainingTTL()
  return Math.ceil(rateLimitCache.getRemainingTTL(ip) / 1000 / 60)
}

function isRateLimited(ip: string): { limited: boolean; minutesLeft: number } {
  const count = rateLimitCache.get(ip) ?? 0
  if (count >= RATE_LIMIT) {
    return { limited: true, minutesLeft: getRemainingTime(ip) }
  }
  // Increment — preserve existing TTL by setting start time
  rateLimitCache.set(ip, count + 1)
  return { limited: false, minutesLeft: 0 }
}

const AUTH_PATHS = ['/api/auth/callback/credentials', '/login', '/register']

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl
  const isAuthPath = AUTH_PATHS.some(p => pathname.startsWith(p))

  if (isAuthPath && request.method === 'POST') {
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
      ?? request.headers.get('x-real-ip')
      ?? '127.0.0.1'

    const { limited, minutesLeft } = isRateLimited(ip)
    if (limited) {
      return new NextResponse(
        JSON.stringify({ error: `Too many attempts. Try again in ${minutesLeft} minutes.` }),
        { status: 429, headers: { 'Content-Type': 'application/json' } }
      )
    }
  }

  // Delegate auth routing to NextAuth (same as current middleware.ts)
  return NextAuth(authConfig).auth(request as Parameters<typeof NextAuth>[0]['auth'][0])
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|.*\\.png$).*)'],
}
```

**Note on NextAuth integration:** The current `middleware.ts` exports `NextAuth(authConfig).auth` as default. In `proxy.ts`, the named export must be `proxy`. The auth check still runs — rate limiting is prepended. Verify the NextAuth import pattern remains compatible (see Open Questions).

### Pattern 2: Sharp Upload Pipeline (SEC-01)

**What:** Replace raw `writeFile` with a sharp pipeline that: validates format via `metadata()`, rejects non-image buffers, re-encodes to WebP, resizes to max 800px.

**When to use:** In `createCard` and `updateCard` wherever image upload is processed.

```typescript
// Source: sharp official docs (https://sharp.pixelplumbing.com/api-output/)
import sharp from 'sharp'

const ALLOWED_FORMATS = ['jpeg', 'png', 'webp'] as const

async function processUploadedImage(buffer: Buffer): Promise<Buffer> {
  // sharp auto-detects format from magic bytes — no file.type needed
  const metadata = await sharp(buffer).metadata()

  if (!metadata.format || !ALLOWED_FORMATS.includes(metadata.format as typeof ALLOWED_FORMATS[number])) {
    throw new Error('Only JPG, PNG, and WebP images are accepted.')
  }

  // Re-encode to WebP: strips EXIF metadata, reduces file size, sanitizes content
  return sharp(buffer)
    .resize(800, 800, {
      fit: 'inside',        // preserve aspect ratio, neither dim exceeds 800px
      withoutEnlargement: true,  // don't upscale small images
    })
    .webp({ quality: 80 })
    .toBuffer()
}
```

**Filename change:** Output files use `.webp` extension. Use `${randomUUID()}.webp` instead of `${randomUUID()}${ext}`.

### Pattern 3: useActionState Migration (QUAL-04)

**What:** React 19 renamed `useFormState` (from `react-dom`) to `useActionState` (from `react`). The API is identical except: (1) import source changes, (2) a third return value `isPending` is available.

**When to use:** All three forms: `add-card-form.tsx`, `edit-form.tsx`, `subscribe/page.tsx`.

```typescript
// BEFORE (deprecated):
import { useFormState } from 'react-dom'
const [errorMessage, dispatch] = useFormState(createCard, undefined)

// AFTER (React 19):
// Source: https://react.dev/blog/2024/12/05/react-19
import { useActionState } from 'react'
const [errorMessage, dispatch, isPending] = useActionState(createCard, undefined)
// isPending can replace the need for a separate useTransition in simple cases
// useFormStatus (from react-dom) is still valid for child SubmitButton components
```

### Pattern 4: File Cleanup on Delete/Update (BUG-02, BUG-03)

**What:** Add `fs.unlink` calls to `deleteCard` and `updateCard` to remove orphaned files.

```typescript
// Source: Node.js fs/promises docs — already imported in actions.ts
import { unlink } from 'fs/promises'
import path from 'path'

// In deleteCard — after prisma.card.delete():
if (card.image) {
  const filePath = path.join(process.cwd(), 'public', card.image)
  await unlink(filePath).catch(() => {}) // best-effort; file may not exist
}

// In updateCard — after new image written, before prisma.card.update():
if (imageFile && imageFile.size > 0 && existingCard.image) {
  const oldPath = path.join(process.cwd(), 'public', existingCard.image)
  await unlink(oldPath).catch(() => {}) // best-effort
}
```

### Pattern 5: next/script for Service Worker (QUAL-05)

**What:** Replace `dangerouslySetInnerHTML` script tag in `app/layout.tsx` with `<Script>` from `next/script`.

```typescript
// Source: Next.js Script component docs
// app/layout.tsx
import Script from 'next/script'

// BEFORE:
<script dangerouslySetInnerHTML={{ __html: `if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js'); }` }} />

// AFTER:
<Script
  id="register-sw"
  strategy="afterInteractive"
  dangerouslySetInnerHTML={{
    __html: `if ('serviceWorker' in navigator) { navigator.serviceWorker.register('/sw.js'); }`,
  }}
/>
// id prop is required by Next.js for inline scripts
// afterInteractive is correct strategy — SW registration is non-critical
```

### Pattern 6: Parallel Logo Search (PERF-03)

**What:** Replace sequential `await fetch(clearbit)` then `await fetch(logo.dev)` with `Promise.all`.

```typescript
// BEFORE (sequential):
const clearbitResponse = await fetch(clearbitUrl)
// ...then later:
const logoDevResponse = await fetch(logoDevUrl)

// AFTER (parallel):
const [clearbitResponse, logoDevResponse] = await Promise.all([
  fetch(clearbitUrl),
  process.env.LOGO_DEV_SECRET
    ? fetch(logoDevUrl, { headers: { Authorization: `Bearer ${process.env.LOGO_DEV_SECRET}` } })
    : Promise.resolve(null),
])
```

### Pattern 7: Barcode Format Validation (SEC-03)

**What:** Validate `barcodeFormat` field against an allowlist before storing. Reject or default unknown formats.

```typescript
// The allowed formats match the UI options in add-card-form.tsx and edit-form.tsx
const ALLOWED_BARCODE_FORMATS = [
  'code128', 'ean13', 'upca', 'qrcode', 'pdf417', 'datamatrix', 'aztec', 'code39'
] as const

type BarcodeFormat = typeof ALLOWED_BARCODE_FORMATS[number]

function validateBarcodeFormat(format: string | null | undefined): BarcodeFormat | null {
  if (!format) return null
  return ALLOWED_BARCODE_FORMATS.includes(format as BarcodeFormat)
    ? (format as BarcodeFormat)
    : null // or throw — reject invalid formats silently (user already chose from dropdown)
}
```

### Anti-Patterns to Avoid

- **Keeping `middleware.ts`:** This file is deprecated in Next.js 16. Rate limiting in the Edge runtime via `middleware.ts` cannot use `lru-cache` reliably (stateless, no shared memory between requests). Always use `proxy.ts` for new logic.
- **Trusting `file.type` header:** The Content-Type from the browser is user-controlled. Always use sharp's `metadata()` which reads actual magic bytes.
- **`unlink` without catch:** File may not exist if previously cleaned. Wrap in `.catch(() => {})` or use `rm` with `{ force: true }`.
- **Sequential external API calls:** Clearbit and logo.dev are independent; sequential awaits double latency for no benefit.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Image format detection | Buffer header slice + manual byte comparison | `sharp(buffer).metadata()` | Sharp uses libvips deep decode — more accurate than header-only check; also catches truncated files |
| Image sanitization | Stream-copy with format check | `sharp().webp().toBuffer()` | Re-encoding through sharp strips polyglot payloads, EXIF data, embedded scripts — copy alone does not sanitize |
| Rate limit TTL tracking | Manual `Map<string, {count, expiry}>` + `setInterval` cleanup | `lru-cache` with `ttl` option | LRU handles eviction automatically; manual cleanup has memory leak risk if `setInterval` fires before GC |
| Redirect loop detection | Complex session flag analysis | Simply ensure `selectPlan` sets `subscriptionSelected = true` before redirect | The existing authorized callback already redirects on `!hasSelectedPlan`; the bug is that "Skip for now" was a Link (no action), not that the logic is wrong |

---

## Common Pitfalls

### Pitfall 1: proxy.ts Export Name Must Be `proxy`

**What goes wrong:** Renaming the file but keeping `export default NextAuth(authConfig).auth` causes "export 'middleware' not found" or the proxy function not running.

**Why it happens:** Next.js 16 requires the named export `proxy` (not `middleware` or `default`) in `proxy.ts`.

**How to avoid:** The export must be:
```typescript
export function proxy(request: NextRequest) { ... }
// or wrap NextAuth:
export function proxy(request: NextRequest) {
  return NextAuth(authConfig).auth(request)
}
```

**Warning signs:** Auth redirects stop working; all routes become accessible.

### Pitfall 2: NextAuth Peer Dependency Warning with Next.js 16

**What goes wrong:** `npm install` reports peer dependency conflict (`next-auth` expects `^12 || ^13 || ^14 || ^15`). Build may fail.

**Why it happens:** `next-auth@5.0.0-beta.30` hasn't officially updated its `peerDependencies` to include Next.js 16 yet (as of Feb 2026).

**How to avoid:** The project already has `next-auth@^5.0.0-beta.30` installed and working. Adding sharp to `package.json` won't trigger a reinstall of next-auth. If `npm install sharp` causes peer resolution errors, use `--legacy-peer-deps`.

**Warning signs:** `npm install` exits with error code due to peer conflict.

### Pitfall 3: Sharp Not Available in Edge Runtime

**What goes wrong:** If sharp is ever called from `proxy.ts` (or any Edge route), the build fails with "sharp is not available in the Edge runtime."

**Why it happens:** Sharp is a native Node.js module (C binding via libvips). It cannot run in Edge.

**How to avoid:** Sharp is only called from Server Actions (`app/lib/actions.ts`), which run in Node.js. Do not import sharp in `proxy.ts`.

**Warning signs:** Build error mentioning `sharp` in Edge context.

### Pitfall 4: lru-cache TTL Resets on Each Increment

**What goes wrong:** Each call to `cache.set(ip, count + 1)` resets the TTL to the full 15 minutes, effectively giving users an unlimited window as long as they keep attempting.

**Why it happens:** `lru-cache.set()` with the default TTL option always uses the cache-level TTL from the time of the current `set()` call.

**How to avoid:** Two approaches:
1. Use a separate timestamp-based key structure: store `{ count, windowStart }` and check elapsed time manually.
2. Use `cache.set(ip, count + 1, { start: windowStartTimestamp })` to anchor the TTL to the first request in the window (requires tracking first-seen time separately).

**Simplest correct approach:** Store the window object:
```typescript
type RateLimitEntry = { count: number }
const cache = new LRUCache<string, RateLimitEntry>({ max: 500, ttl: 15 * 60 * 1000 })
// Set only on first request (uses cache-level TTL anchored to first set)
// Subsequent requests: get existing entry and mutate count
const entry = cache.get(ip)
if (!entry) {
  cache.set(ip, { count: 1 })
} else {
  entry.count++ // mutates in place without resetting TTL
}
```

**Warning signs:** Users can bypass 5-attempt limit by spacing attempts more than a few seconds apart.

### Pitfall 5: Prisma Migration Needed for onboardingComplete Removal

**What goes wrong:** Deleting `onboardingComplete` from the Prisma schema without running a migration leaves the column in the database, causing Prisma type errors.

**Why it happens:** Prisma's generated client reflects the schema. If the schema is changed but no migration is run, the DB and client are out of sync.

**How to avoid:** After removing `onboardingComplete` from `schema.prisma`:
```bash
npx prisma migrate dev --name remove-onboarding-complete
npx prisma generate
```

**Warning signs:** TypeScript errors on `user.onboardingComplete` or runtime errors accessing the column.

### Pitfall 6: BUG-01 Root Cause Is the "Skip for now" Link, Not the Auth Logic

**What goes wrong:** The "Skip for now" link at the top of the subscribe page is a `<Link href="/dashboard">` — a plain navigation that never calls `selectPlan`. The authorized callback sees `!hasSelectedPlan` and redirects back to `/subscribe`. Infinite loop.

**Why it happens:** `subscriptionSelected` is never set to `true` via the Link. The fix is removing the Link entirely and replacing both "Choose Free" and "Skip for now" with a single button that calls `selectPlan`-equivalent action.

**How to avoid:** The new "Continue with Free" button submits a form action that upserts the subscription + sets `subscriptionSelected = true` + redirects to dashboard. No `<Link>` for navigation past the subscribe wall.

**Warning signs:** User clicks "Skip" and ends up back on subscribe page immediately.

---

## Code Examples

Verified patterns from official sources:

### Sharp: Validate and Re-encode
```typescript
// Source: https://sharp.pixelplumbing.com/api-output/
import sharp from 'sharp'

const ALLOWED_FORMATS = ['jpeg', 'png', 'webp']

async function validateAndConvertImage(buffer: Buffer): Promise<Buffer> {
  let metadata
  try {
    metadata = await sharp(buffer).metadata()
  } catch {
    throw new Error('Only JPG, PNG, and WebP images are accepted.')
  }

  if (!metadata.format || !ALLOWED_FORMATS.includes(metadata.format)) {
    throw new Error('Only JPG, PNG, and WebP images are accepted.')
  }

  return sharp(buffer)
    .resize(800, 800, { fit: 'inside', withoutEnlargement: true })
    .webp({ quality: 80 })
    .toBuffer()
}
```

### lru-cache: Rate Limit Window (Correct TTL Anchoring)
```typescript
// Source: https://www.npmjs.com/package/lru-cache
import { LRUCache } from 'lru-cache'

type Window = { count: number }

const windows = new LRUCache<string, Window>({
  max: 500,
  ttl: 15 * 60 * 1000,  // 15 minutes
})

function checkRateLimit(ip: string, limit: number): { allowed: boolean; minutesLeft: number } {
  const existing = windows.get(ip)

  if (!existing) {
    windows.set(ip, { count: 1 })
    return { allowed: true, minutesLeft: 0 }
  }

  if (existing.count >= limit) {
    const ms = windows.getRemainingTTL(ip)
    return { allowed: false, minutesLeft: Math.ceil(ms / 60000) }
  }

  existing.count++  // mutate in place — does NOT reset TTL
  return { allowed: true, minutesLeft: 0 }
}
```

### useActionState: Form Migration
```typescript
// Source: https://react.dev/blog/2024/12/05/react-19
// BEFORE:
import { useFormState } from 'react-dom'
const [state, formAction] = useFormState(serverAction, initialState)

// AFTER:
import { useActionState } from 'react'
const [state, formAction, isPending] = useActionState(serverAction, initialState)
// useFormStatus (child components) stays in react-dom — no change needed
```

### selectPlan Rework: BUG-01 Fix
```typescript
// actions.ts — simplified selectPlan (now "continueWithFree")
export async function continueWithFree() {
  const session = await auth()
  if (!session?.user?.email) return { error: 'Not authenticated' }

  const user = await prisma.user.findUnique({
    where: { email: session.user.email },
    select: { id: true },
  })
  if (!user) return { error: 'User not found' }

  await prisma.subscription.upsert({
    where: { userId: user.id },
    update: { tier: 'FREE', status: 'ACTIVE' },
    create: { userId: user.id, tier: 'FREE', status: 'ACTIVE' },
  })

  await prisma.user.update({
    where: { id: user.id },
    data: { subscriptionSelected: true },
  })

  redirect('/dashboard')
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `middleware.ts` (Edge runtime) | `proxy.ts` (Node.js runtime) | Next.js 16 (Oct 2025) | lru-cache works natively; no Redis needed |
| `useFormState` from `react-dom` | `useActionState` from `react` | React 19 (Dec 2024) | Must migrate to remove deprecation warning |
| Raw file copy (`writeFile`) for uploads | sharp re-encode pipeline | Best practice | Sanitizes uploads, strips EXIF, reduces size |

**Deprecated/outdated:**
- `middleware.ts`: Deprecated in Next.js 16. The project should rename to `proxy.ts` as part of this phase.
- `useFormState` from `react-dom`: Deprecated in React 19. Already triggers console warnings.
- `dangerouslySetInnerHTML` for scripts: Not deprecated, but `next/script` is the recommended approach and avoids CSP issues.

---

## Open Questions

1. **NextAuth integration with proxy.ts**
   - What we know: The current `middleware.ts` exports `NextAuth(authConfig).auth` as the default. The community confirms renaming to `proxy.ts` works with the named `proxy` export.
   - What's unclear: The exact import/export pattern for wrapping NextAuth's auth check inside the `proxy` function alongside rate limiting has not been verified against next-auth@5.0.0-beta.30 specifically.
   - Recommendation: During implementation, test `export function proxy(request) { return NextAuth(authConfig).auth(request) }` first. If it fails, fall back to running auth check separately via `auth()` inside the proxy function body.

2. **Rate limit bypass for Server Actions vs. route-level**
   - What we know: The `authenticate` server action in `actions.ts` calls `signIn('credentials', formData)` — this goes through NextAuth's credentials flow at `/api/auth/callback/credentials`. The proxy intercepts this path.
   - What's unclear: Whether form submissions to server actions hit `/api/auth` paths or a different route.
   - Recommendation: Intercept both `/api/auth/callback/credentials` and POST to `/login` and `/register` paths in the matcher. Verify by submitting the form and checking which URL appears in network tab.

3. **lru-cache getRemainingTTL availability**
   - What we know: `getRemainingTTL(key)` is documented in lru-cache v10+.
   - What's unclear: The exact installed version (package.json shows no lru-cache dependency — it may be a transitive dep of next-auth).
   - Recommendation: Run `npm ls lru-cache` to check version. If not installed or < v10, install `lru-cache@^11` explicitly.

---

## Sources

### Primary (HIGH confidence)
- [Next.js 16 Blog Post](https://nextjs.org/blog/next-16) — proxy.ts replacing middleware.ts, Node.js runtime
- [Next.js proxy.ts file convention docs](https://nextjs.org/docs/app/api-reference/file-conventions/proxy) — export syntax
- [React 19 Blog Post](https://react.dev/blog/2024/12/05/react-19) — useActionState migration
- [sharp official docs](https://sharp.pixelplumbing.com/api-output/) — metadata(), WebP output API
- [lru-cache npm page](https://www.npmjs.com/package/lru-cache) — TTL configuration, getRemainingTTL
- [Next.js Script component docs](https://nextjs.org/docs/app/api-reference/components/script) — afterInteractive, id requirement

### Secondary (MEDIUM confidence)
- [NextAuth v5 + Next.js 16 GitHub issue #13302](https://github.com/nextauthjs/next-auth/issues/13302) — peer dep workaround confirmed working
- [Next.js upgrading to v16 guide](https://nextjs.org/docs/app/guides/upgrading/version-16) — breaking changes list
- [Next.js middleware-to-proxy rename docs](https://nextjs.org/docs/messages/middleware-to-proxy) — migration steps

### Tertiary (LOW confidence)
- Community articles on lru-cache rate limiting pattern — general pattern verified against npm docs; specific proxy.ts integration untested

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — sharp and lru-cache are well-documented; next/script is built-in
- Architecture (proxy.ts): HIGH — confirmed by official Next.js 16 release notes
- React 19 migration: HIGH — confirmed by official React 19 blog post
- Rate limiting lru-cache TTL anchoring: MEDIUM — pattern is correct per docs but integration with proxy.ts + NextAuth needs implementation verification
- Pitfalls: HIGH for known bugs (BUG-01 root cause); MEDIUM for lru-cache TTL edge case

**Research date:** 2026-02-28
**Valid until:** 2026-03-28 (stable libraries; proxy.ts is a stable Next.js 16 feature)
