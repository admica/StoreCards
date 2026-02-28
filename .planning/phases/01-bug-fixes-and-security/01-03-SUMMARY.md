---
phase: 01-bug-fixes-and-security
plan: 03
subsystem: frontend
tags: [refactor, deduplication, react19, hooks]
dependency_graph:
  requires: [01-01, 01-02]
  provides: [useBarcodeScanner-hook, cacheBrandLogo-helper, useActionState-migration]
  affects: [app/hooks, app/add, app/card/edit, app/lib/actions, app/subscribe, app/register, app/login]
tech_stack:
  added: []
  patterns: [custom-hook-extraction, helper-function-extraction, react19-useActionState]
key_files:
  created:
    - app/hooks/useBarcodeScanner.ts
  modified:
    - app/add/add-card-form.tsx
    - app/card/[id]/edit/edit-form.tsx
    - app/lib/actions.ts
    - app/subscribe/page.tsx
    - app/register/page.tsx
    - app/login/page.tsx
    - eslint.config.mjs
decisions:
  - "useBarcodeScanner hook accepts optional initialBarcodeValue/initialBarcodeFormat for edit mode compatibility"
  - "handleImageUpload wrapper in forms keeps preview logic local and delegates scanning to hook"
  - "Added .claude/** to eslint ignores — pre-existing CJS tooling files caused lint errors"
metrics:
  duration: ~5 min
  completed: 2026-02-28
  tasks_completed: 2
  files_changed: 7
---

# Phase 1 Plan 3: Code Deduplication and React 19 Migration Summary

**One-liner:** Extracted 150-line barcode scanning logic into `useBarcodeScanner` hook, deduplicated `cacheBrandLogo` helper, and migrated all 5 forms from deprecated `useFormState` to React 19 `useActionState`.

## Tasks Completed

| # | Task | Commit | Status |
|---|------|--------|--------|
| 1 | Extract useBarcodeScanner hook (QUAL-01) and cacheBrandLogo helper (QUAL-02) | f75e29e | Done |
| 2 | Migrate useFormState to useActionState (QUAL-04) | 2c241f4 | Done |

## What Was Built

### Task 1: useBarcodeScanner Hook + cacheBrandLogo Helper

**`app/hooks/useBarcodeScanner.ts`** — New custom hook that encapsulates:
- ZXing `BrowserMultiFormatReader` with `TRY_HARDER` hints
- `useZxing` camera scanning with pause/resume
- Multi-rotation fallback (preprocessed canvas → rotated canvases → direct image element)
- State: `scannedResult`, `detectedFormat`, `isScanning`, `scanStatus`
- Returns: all state + setters + `ref` for video element + `handleImageUpload`
- Accepts `initialBarcodeValue` and `initialBarcodeFormat` for edit mode

**`app/lib/actions.ts`** — Extracted `cacheBrandLogo(retailer, logo, colorLight?, colorDark?)` private helper that normalizes the retailer name and upserts `BrandLogo`. Called by both `createCard` and `updateCard` instead of ~20 lines of duplicated code each.

### Task 2: React 19 Migration

All 5 form files migrated from `useFormState` (react-dom) to `useActionState` (react):
- `app/add/add-card-form.tsx` — createCard form
- `app/card/[id]/edit/edit-form.tsx` — updateCard form
- `app/subscribe/page.tsx` — continueWithFree form
- `app/register/page.tsx` — register form
- `app/login/page.tsx` — authenticate form

`useFormStatus` imports from `react-dom` preserved (correct — this hook stays in react-dom).

## Verification

- `npm run build` passes
- `npm run lint` passes (0 errors, 6 warnings — all intentional `_isPending` variables)
- No `useFormState` imports remain in `app/`
- `useBarcodeScanner` hook imported in both add-card-form and edit-form
- `cacheBrandLogo` helper defined once, called at 2 sites

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Config] Added `.claude/**` to eslint ignores**
- **Found during:** Task 2 lint verification
- **Issue:** ESLint was scanning `.claude/get-shit-done/bin/*.cjs` tooling files (CommonJS require syntax), causing 70 lint errors that blocked the plan's success criteria
- **Fix:** Added `.claude/**` glob to `globalIgnores` in `eslint.config.mjs`
- **Files modified:** `eslint.config.mjs`
- **Commit:** 2c241f4

## Self-Check: PASSED

All created files verified present. Both task commits verified in git log.
