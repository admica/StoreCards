---
phase: 02-ux-quality-and-error-handling
plan: 01
subsystem: ui
tags: [sonner, zod, react, barcode, toast, validation, tailwind]

# Dependency graph
requires:
  - phase: 01-bug-fixes-and-security
    provides: Barcode.tsx baseline, layout.tsx with ThemeProvider, app/providers/theme-provider.tsx with useTheme hook
provides:
  - SubmitButton shared component with useFormStatus spinner + pending label
  - ToasterWithTheme wired to ThemeContext for light/dark-aware toasts
  - Zod client validation schemas (loginSchema, registerSchema, cardSchema, validateField)
  - Barcode error fallback showing raw value + clipboard copy button
  - Dashboard empty state with "Add your first card" CTA
affects:
  - 02-02 (login/register forms consume validation.ts + SubmitButton)
  - 02-03 (card forms consume validation.ts + SubmitButton + toast)

# Tech tracking
tech-stack:
  added: [sonner@^1.x (toast notifications), zod (already present, now used client-side)]
  patterns:
    - useFormStatus-based SubmitButton pattern replacing inline LoginButton
    - ThemeContext-bridged Toaster (useTheme() -> sonner theme prop)
    - Barcode error state with navigator.clipboard.writeText fallback
    - Zod schema + validateField helper for reusable blur validation

key-files:
  created:
    - app/components/SubmitButton.tsx
    - app/components/ToasterWithTheme.tsx
    - app/lib/validation.ts
  modified:
    - app/components/Barcode.tsx
    - app/layout.tsx
    - app/dashboard/page.tsx

key-decisions:
  - "validateField uses ZodTypeAny cast on schema.shape[name] — required for TypeScript to resolve safeParse() in Zod v4"
  - "ToasterWithTheme uses position top-center — BottomNav is fixed at bottom (~80px) so bottom toast position would collide"
  - "Barcode copy fallback uses inline copied state (not toast) — compact context where a toast would feel heavy-handed"

patterns-established:
  - "SubmitButton pattern: import { SubmitButton } from '@/app/components/SubmitButton' — replaces inline button+spinner in each form"
  - "Toast pattern: import { toast } from 'sonner'; toast.success('...') — ToasterWithTheme already in layout"
  - "Validation pattern: validateField(loginSchema, 'email', value) returns string | null for field-level error display"

requirements-completed: [BUG-04, UX-03, UX-04, UX-05]

# Metrics
duration: 8min
completed: 2026-02-28
---

# Phase 02 Plan 01: UX Foundation Components Summary

**Sonner toast infrastructure, shared SubmitButton with spinner, Zod client validation schemas, and Barcode error fallback with clipboard copy — foundational components for all Phase 2 UX polish**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-02-28T23:09:25Z
- **Completed:** 2026-02-28T23:17:00Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Installed sonner and created ToasterWithTheme wired to ThemeContext (top-center, richColors, dark/light aware)
- Created SubmitButton shared component with useFormStatus pending state, spinner, and configurable labels
- Created validation.ts with Zod schemas (loginSchema, registerSchema, cardSchema) and validateField helper
- Fixed BUG-04: Barcode.tsx now shows raw number + copy button with 2s "Copied" confirmation when bwip-js fails
- Enhanced dashboard empty state CTA from "Add First Card" to "Add your first card" (UX-03)

## Task Commits

Each task was committed atomically:

1. **Task 1: Install sonner, create shared components and validation schemas** - `89e200d` (feat)
2. **Task 2: Add Barcode error fallback, wire Toaster into layout, enhance empty state** - `cc8afdd` (feat)

## Files Created/Modified

- `app/components/SubmitButton.tsx` - Shared submit button with useFormStatus, spinner, pending/idle labels
- `app/components/ToasterWithTheme.tsx` - Sonner Toaster bridged to ThemeContext via useTheme()
- `app/lib/validation.ts` - Zod schemas + validateField helper for client-side blur validation
- `app/components/Barcode.tsx` - Added error state with raw value display + navigator.clipboard copy button
- `app/layout.tsx` - Added ToasterWithTheme inside ThemeProvider children
- `app/dashboard/page.tsx` - Updated CTA text to "Add your first card"

## Decisions Made

- **validateField TypeScript cast**: `schema.shape[name]` returns `$ZodType<unknown>` in Zod v4 which lacks `safeParse`. Cast to `ZodTypeAny` resolves the type error cleanly without runtime impact.
- **Toast position top-center**: BottomNav is fixed at ~80px from bottom — bottom-positioned toasts would overlay navigation. top-center avoids collision.
- **Barcode copy uses inline state**: The barcode error fallback is compact; a full toast for "Copied" would feel disproportionate. Inline checkmark for 2s is the right UX for this context.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed TypeScript type error in validateField**
- **Found during:** Task 2 (build verification)
- **Issue:** `schema.shape[name]` in Zod v4 returns `$ZodType<unknown>` which doesn't expose `.safeParse()` at the TypeScript level
- **Fix:** Cast to `z.ZodTypeAny` via `as z.ZodTypeAny | undefined` — preserves runtime behavior, satisfies TypeScript compiler
- **Files modified:** `app/lib/validation.ts`
- **Verification:** Build passes with no type errors
- **Committed in:** `cc8afdd` (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - TypeScript type bug)
**Impact on plan:** Required for build to pass. No scope creep, no behavior change.

## Issues Encountered

- Zod v4 changed internal type names — `ZodObject.shape[name]` returns an internal opaque type in strict TypeScript mode. Cast to `ZodTypeAny` is the documented workaround.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- SubmitButton, ToasterWithTheme, and validation schemas ready for consumption by Plans 02 and 03
- Plans 02 and 03 can proceed immediately — all shared infrastructure is in place
- No blockers

---
*Phase: 02-ux-quality-and-error-handling*
*Completed: 2026-02-28*
