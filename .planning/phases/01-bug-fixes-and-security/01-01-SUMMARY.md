---
phase: 01-bug-fixes-and-security
plan: 01
subsystem: auth
tags: [nextauth, sharp, prisma, image-upload, barcode, stripe]

# Dependency graph
requires: []
provides:
  - continueWithFree server action (replaces selectPlan) — sets subscriptionSelected=true and redirects to dashboard
  - processUploadedImage helper — sharp-based magic-byte validation and WebP re-encoding at 800px max
  - validateBarcodeFormat helper — 8-format allowlist for barcode format DB storage
  - File cleanup on card delete and card image replacement (unlink)
  - Parallel logo search via Promise.allSettled for Clearbit + logo.dev
affects: [02-bug-fixes-and-security, 03-ui-polish]

# Tech tracking
tech-stack:
  added: [sharp@latest]
  patterns: [sharp-pipeline, magic-byte-validation, parallel-api-calls, server-action-redirect]

key-files:
  created: []
  modified:
    - app/lib/actions.ts
    - app/subscribe/page.tsx
    - auth.ts

key-decisions:
  - "continueWithFree takes _prevState for useFormState compatibility; QUAL-04 in Plan 03 handles migration to useActionState"
  - "Image re-encoding always produces .webp regardless of original format — consistent extension, smaller files"
  - "Barcode format allowlist stores lowercase values — normalizes inconsistent client input"
  - "Old image file deleted after new file written successfully — avoids orphaning if write fails"

patterns-established:
  - "processUploadedImage: validate magic bytes via sharp, reject non-image content, resize+encode to WebP"
  - "validateBarcodeFormat: lowercase allowlist check returns null for unknown formats (stored as null in DB)"
  - "File cleanup via unlink().catch(() => {}) — best-effort, never blocks the primary operation"

requirements-completed: [BUG-01, BUG-02, BUG-03, SEC-01, SEC-03, PERF-03]

# Metrics
duration: 8min
completed: 2026-02-28
---

# Phase 01 Plan 01: Bug Fixes and Security — Subscribe, Uploads, Cleanup Summary

**Closed subscribe redirect loop, hardened image uploads with sharp magic-byte validation and WebP re-encoding, added file cleanup on delete/replace, validated barcode formats against allowlist, and parallelized Clearbit+logo.dev logo search**

## Performance

- **Duration:** 8 min
- **Started:** 2026-02-28T20:48:19Z
- **Completed:** 2026-02-28T20:56:31Z
- **Tasks:** 2
- **Files modified:** 4 (app/lib/actions.ts, app/subscribe/page.tsx, auth.ts, package.json)

## Accomplishments
- Fixed subscribe redirect loop (BUG-01): replaced `selectPlan` with `continueWithFree` action that sets `subscriptionSelected=true` before redirecting — the root cause was the "Skip for now" Link bypassing the action entirely
- Hardened image uploads (SEC-01): sharp validates magic bytes, rejects non-image files, resizes to 800px max, re-encodes to WebP at 80% quality
- Added disk cleanup (BUG-02, BUG-03): `deleteCard` and `updateCard` now remove old image files from `public/uploads/` via `unlink()`
- Validated barcode formats (SEC-03): 8-format allowlist (`code128`, `ean13`, `upca`, `qrcode`, `pdf417`, `datamatrix`, `aztec`, `code39`) prevents arbitrary strings reaching the DB
- Parallelized logo search (PERF-03): Clearbit and logo.dev API calls now run concurrently via `Promise.allSettled`

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix subscribe flow (BUG-01) and subscribe page UI** - `22e374d` (feat)
2. **Task 2: Image security, file cleanup, barcode validation, parallel logos** - `10787ab` (feat)

**Plan metadata:** (docs commit — see final commit)

## Files Created/Modified
- `app/lib/actions.ts` — Added processUploadedImage, validateBarcodeFormat, continueWithFree; updated createCard/updateCard/deleteCard/searchLogos
- `app/subscribe/page.tsx` — Removed "Skip for now" Link, replaced with single "Continue with Free" form button
- `auth.ts` — Removed non-existent `onboardingComplete` field from authorize return (Rule 1 auto-fix)
- `package.json` — Added sharp dependency

## Decisions Made
- `continueWithFree` keeps `_prevState` parameter for `useFormState` compatibility; QUAL-04 in Plan 03 handles the migration to `useActionState`
- Image re-encoding always produces `.webp` output regardless of input format — consistent file extension, better compression, no need to preserve original format
- Barcode format allowlist normalizes to lowercase — clients may send mixed case, DB stores lowercase for consistency
- Old image file deleted only after new file is written successfully — prevents losing the old image if the new upload fails midway

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed non-existent `onboardingComplete` field from auth.ts**
- **Found during:** Task 1 (build verification)
- **Issue:** `auth.ts` referenced `user.onboardingComplete` in the `authorize` callback return, but the Prisma schema has no such field — TypeScript compilation error
- **Fix:** Removed `onboardingComplete: user.onboardingComplete` from the authorize return object
- **Files modified:** `auth.ts`
- **Verification:** `npm run build` passed after fix
- **Committed in:** `22e374d` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - bug)
**Impact on plan:** Fix was necessary for build to pass. No scope creep — removed stale field reference from pre-existing code.

## Issues Encountered
- Transient build failures due to `.next` lock file race condition between consecutive build runs — resolved by adding brief sleep between runs. Not related to code changes.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Subscribe redirect loop fixed — new users can now complete onboarding without getting stuck
- Image upload pipeline is secure against file extension spoofing
- Disk usage will no longer grow unbounded from orphaned upload files
- Plan 02 (additional bug fixes) can proceed without blockers from this plan

---
*Phase: 01-bug-fixes-and-security*
*Completed: 2026-02-28*
