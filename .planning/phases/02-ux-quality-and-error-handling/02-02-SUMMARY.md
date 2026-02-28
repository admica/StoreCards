---
phase: 02-ux-quality-and-error-handling
plan: 02
subsystem: ui
tags: [react, zxing, react-zxing, zod, validation, barcode, camera, error-handling]

# Dependency graph
requires:
  - phase: 02-01
    provides: "SubmitButton component, cardSchema/validateField from validation.ts"

provides:
  - "ScanErrorType union type and categorized error state in useBarcodeScanner hook"
  - "startScanning() with proactive camera permission check via navigator.permissions.query"
  - "clearScanError() to reset error state"
  - "permission-denied error panel replacing camera view in both card forms"
  - "camera-not-found error panel replacing camera view in both card forms"
  - "decode-failure overlay with Try Again button for image upload scan failures"
  - "Retailer field blur validation with error border and error message in both card forms"
  - "Both card forms now use shared SubmitButton from Plan 01"

affects:
  - 02-03
  - 03-login-register-ux

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "ScanErrorType discrimination: hook categorizes errors; UI renders per-type panels"
    - "Proactive permission check pattern: navigator.permissions.query before useZxing activation"
    - "Blur validation with live error clearing: validate on blur, clear on valid keystroke"
    - "Error-replacement UI: camera errors replace the camera view (not toast/overlay)"

key-files:
  created: []
  modified:
    - app/hooks/useBarcodeScanner.ts
    - app/add/add-card-form.tsx
    - app/card/[id]/edit/edit-form.tsx

key-decisions:
  - "Scan errors (permission-denied, camera-not-found) replace the camera view entirely — not overlaid — for maximum clarity when camera is unavailable"
  - "decode-failure shown as an overlay banner (not replacing camera view) since the camera section is not visible during image upload flow"
  - "onError in useZxing catches post-init NotAllowedError/NotFoundError; startScanning() checks permissions proactively for pre-init denials"
  - "clearScanError resets both scanErrorType and scanStatus to allow retry without page reload"

patterns-established:
  - "Error type discrimination pattern: ScanErrorType drives conditional rendering in consuming components"
  - "Proactive permission pattern: check navigator.permissions before activating hardware access"
  - "Progressive blur validation: validate on blur, actively clear on valid keystrokes (no re-trigger on blur)"

requirements-completed: [UX-01, UX-02]

# Metrics
duration: 12min
completed: 2026-02-28
---

# Phase 2 Plan 02: Scan Error Handling and Blur Validation Summary

**Categorized camera/barcode scan errors with per-type UI panels and retailer field blur validation in both card forms, replacing inline SubmitButton with shared component**

## Performance

- **Duration:** ~12 min
- **Started:** 2026-02-28T23:18:00Z
- **Completed:** 2026-02-28T23:30:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments
- Extended useBarcodeScanner with ScanErrorType discrimination (permission-denied, camera-not-found, decode-failure), proactive navigator.permissions.query check in startScanning(), and clearScanError() helper
- Both card forms (add-card-form, edit-form) show contextual error panels: permission-denied and camera-not-found replace the camera view, decode-failure shows as an inline banner with a "Try again" button
- Retailer field validates on blur using cardSchema/validateField, shows error border and message, clears automatically on valid input
- Removed local SubmitButton from both forms; now using shared SubmitButton from Plan 01

## Task Commits

Each task was committed atomically:

1. **Task 1: Extend useBarcodeScanner with categorized error types** - `b5f44fd` (feat)
2. **Task 2: Wire scan error UI + blur validation into add-card-form and edit-form** - `7a070be` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified
- `app/hooks/useBarcodeScanner.ts` - Added ScanErrorType, scanErrorType state, onError callback, startScanning(), clearScanError(), decode-failure on image upload catch
- `app/add/add-card-form.tsx` - Permission/camera-not-found error panels, decode-failure overlay, blur validation, shared SubmitButton
- `app/card/[id]/edit/edit-form.tsx` - Same changes as add-card-form; kept initialBarcodeValue/Format options; local SubmitButton removed

## Decisions Made
- Scan errors that prevent camera use (permission-denied, camera-not-found) replace the camera view entirely rather than showing as toasts — this is clearer when the camera cannot be used at all
- decode-failure shows inline below the scan section with a "Try again" button to reset state without leaving the form
- onError added to useZxing for post-init failures, but startScanning() also proactively queries permissions to catch pre-init denials that useZxing may not surface via onError

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None - TypeScript compiled cleanly on first attempt for both tasks, build passed without errors.

## User Setup Required
None - no external service configuration required.

## Self-Check: PASSED

All files verified present and both task commits confirmed.

## Next Phase Readiness
- Scan error handling complete for both card forms
- Blur validation for retailer field wired in both forms
- Shared SubmitButton now used throughout card add/edit flows
- Ready for Plan 03 (login/register form validation and remaining UX tasks)

---
*Phase: 02-ux-quality-and-error-handling*
*Completed: 2026-02-28*
