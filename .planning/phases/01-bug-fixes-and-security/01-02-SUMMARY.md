---
phase: 01-bug-fixes-and-security
plan: 02
subsystem: auth
tags: [nextauth, rate-limiting, lru-cache, prisma, middleware, security, pwa]

# Dependency graph
requires: []
provides:
  - LRU-cache rate limiter blocking 6th auth POST attempt per IP in 15-minute window
  - proxy.ts replacing middleware.ts with rate limiting on /login, /register, /api/auth/callback/credentials
  - Prisma schema without onboardingComplete field (migration applied)
  - auth.config.ts without onboardingComplete references
  - app/layout.tsx using next/script for SW registration (CSP-safe)
affects: [auth, security, pwa, middleware]

# Tech tracking
tech-stack:
  added: [lru-cache@11 (direct dep)]
  patterns: [proxy.ts for Next.js 16 middleware with rate limiting, next/script for inline scripts]

key-files:
  created:
    - app/lib/rate-limit.ts
    - proxy.ts
    - prisma/migrations/20260228204958_remove_onboarding_complete/migration.sql
  modified:
    - auth.config.ts
    - app/lib/color-utils.ts
    - app/layout.tsx
    - prisma/schema.prisma
    - package.json

key-decisions:
  - "proxy.ts uses named export (not default) per Next.js 16 middleware convention; middleware.ts deleted"
  - "Rate limit mutates count in place to avoid resetting TTL on each attempt — anchors window to first attempt"
  - "eslint-disable used for auth() cast in proxy.ts — NextAuth overload resolution requires it, not a real any"
  - "Script strategy=afterInteractive for SW registration — non-blocking, CSP-compliant vs raw script in head"

patterns-established:
  - "Rate limiting: checkRateLimit(ip) returns {allowed, minutesLeft} — call before processing auth routes"
  - "proxy.ts pattern: rate limit check -> NextAuth delegation for all route protection"

requirements-completed: [SEC-02, QUAL-03, QUAL-05]

# Metrics
duration: 6min
completed: 2026-02-28
---

# Phase 1 Plan 02: Rate Limiting and Dead Code Removal Summary

**LRU-cache IP rate limiter on auth endpoints (5 attempts/15min), onboardingComplete schema removal with migration, and CSP-safe SW registration via next/script**

## Performance

- **Duration:** 6 min
- **Started:** 2026-02-28T20:48:46Z
- **Completed:** 2026-02-28T20:54:50Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- Rate limiting blocks 6th login/register attempt per IP within 15 minutes with 429 + countdown message
- proxy.ts replaces middleware.ts with equivalent auth routing plus rate limiting on auth POST endpoints
- onboardingComplete field removed from schema, migration applied, all references cleaned from auth.config.ts
- extractColorsFromUrl stub deleted, empty email verification directories removed
- Layout now uses next/script with afterInteractive strategy for SW registration (CSP-safe)

## Task Commits

Each task was committed atomically:

1. **Task 1: Add rate limiting via proxy.ts (SEC-02)** - `8d03555` (feat)
2. **Task 2: Remove dead code (QUAL-03) and replace SW script (QUAL-05)** - `54228a4` (feat)

**Plan metadata:** (docs commit below)

## Files Created/Modified
- `app/lib/rate-limit.ts` - LRU-cache based rate limiter with 500-entry max, 15min TTL
- `proxy.ts` - Next.js 16 proxy middleware with rate limiting + NextAuth delegation
- `middleware.ts` - DELETED (replaced by proxy.ts)
- `prisma/schema.prisma` - Removed onboardingComplete field
- `prisma/migrations/20260228204958_remove_onboarding_complete/migration.sql` - Migration
- `auth.config.ts` - Removed all onboardingComplete references from types and callbacks
- `app/lib/color-utils.ts` - Deleted extractColorsFromUrl stub function
- `app/layout.tsx` - Replaced raw <script> in <head> with next/script Script component
- `package.json` - Added lru-cache as direct dependency

## Decisions Made
- Used `eslint-disable-next-line` for the `auth()` cast in proxy.ts rather than fighting TypeScript overload resolution — the NextAuth `auth` function's union type cannot be narrowed without casting
- Rate limit mutates count in place (not cache.set) to preserve TTL anchor at first attempt — this is the correct behavior for a fixed-window rate limiter
- Deleted middleware.ts entirely since Next.js 16 uses proxy.ts convention

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed no-explicit-any lint error in proxy.ts**
- **Found during:** Task 1 verification (build)
- **Issue:** `auth(request as any)` triggered `@typescript-eslint/no-explicit-any` lint rule
- **Fix:** Extracted `authMiddleware` cast with eslint-disable comment; tried NextAuthRequest import but `next-auth/lib` is not a public export
- **Files modified:** proxy.ts
- **Verification:** Build passes, no new lint errors in modified files
- **Committed in:** `54228a4` (included in Task 2 commit as part of ongoing proxy.ts work)

---

**Total deviations:** 1 auto-fixed (Rule 1 - bug)
**Impact on plan:** Necessary fix for lint compliance. No scope creep.

## Issues Encountered
- Turbopack build intermittently fails with ENOENT on `_buildManifest.js.tmp.*` — resolved by clearing `.next/` cache and rebuilding. This is a pre-existing Turbopack race condition on this machine, not introduced by these changes.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Rate limiting is live on auth endpoints — brute force protection active
- Dead code removed — codebase is cleaner
- Ready for Plan 03 (input validation and type safety hardening)

---
*Phase: 01-bug-fixes-and-security*
*Completed: 2026-02-28*
