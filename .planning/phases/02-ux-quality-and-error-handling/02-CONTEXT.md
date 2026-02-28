# Phase 2: UX Quality and Error Handling - Context

**Gathered:** 2026-02-28
**Status:** Ready for planning

<domain>
## Phase Boundary

Users get actionable feedback when things go wrong and a polished experience throughout the core card workflow. This covers: barcode render/scan error handling, client-side form validation, loading/pending states on server action buttons, and a toast notification system for non-blocking errors. No new features — only error feedback, validation, and loading polish on existing flows.

</domain>

<decisions>
## Implementation Decisions

### Barcode render failures (BUG-04)
- When bwip-js fails to render, replace the canvas area with a styled fallback showing the raw barcode number and a copy button
- Fallback should occupy the same space as the barcode canvas would — inline replacement, not a separate card
- Copy-to-clipboard confirmation: Claude's discretion on toast vs inline checkmark

### Barcode scan errors (UX-01)
- Error presentation should be context-dependent by error type:
  - Permission denied / camera not found: replace the camera view with an error state (icon + message + action)
  - Decode failure: overlay on the camera feed with retry option
- After decode failure, show the error message with retry — manual entry fields already exist elsewhere on the form
- Categorize errors into: permission denied, camera not found, decode failure — each with specific remediation text

### Form validation (UX-02)
- Claude's discretion on validation timing (blur, blur+change, or similar)
- Claude's discretion on error styling — should fit the existing rounded-xl / accent-ring design system
- Claude's discretion on whether to use shared Zod schemas or plain client-side checks
- Claude's discretion on what card form fields need validation beyond 'required'
- Forms in scope: register, login, add card, edit card

### Loading & pending states (UX-04)
- Claude's discretion on spinner + text pattern (existing LoginButton uses spinner + "Signing in...")
- Claude's discretion on disabled behavior during pending
- Claude's discretion on scope — which actions beyond form submits need loading states
- Claude's discretion on whether to create a shared SubmitButton component

### Toast notifications (UX-05)
- Use sonner library as specified in requirements
- Claude's discretion on toast position (considering mobile-first layout with BottomNav)
- Claude's discretion on toast vs inline error split
- Claude's discretion on auto-dismiss duration and behavior
- Claude's discretion on theme customization level (match app theme vs sonner defaults)

### Empty state (UX-03)
- Dashboard already has a basic empty state with icon + "Add First Card" CTA
- May need refinement to match the success criterion ("illustration and 'Add your first card' call-to-action")
- Claude's discretion on whether existing empty state meets the requirement or needs enhancement

### Claude's Discretion
All implementation decisions for this phase are at Claude's discretion. The user trusts Claude to make the best UX choices based on existing codebase patterns, modern best practices, and the success criteria defined in the roadmap. Key areas of flexibility:
- Visual styling of all error states and loading indicators
- Validation approach and library choice
- Toast configuration and theming
- Component architecture (shared vs inline)
- Scope of loading state coverage

</decisions>

<specifics>
## Specific Ideas

No specific requirements — open to standard approaches. User deferred all implementation choices to Claude's judgment.

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `useBarcodeScanner` hook (`app/hooks/useBarcodeScanner.ts`): Has `scanStatus` state that could be enhanced with categorized error types
- `Barcode.tsx` component: Needs error state added — currently silently fails with `console.error`
- `LoginButton` pattern: Uses `useFormStatus` for spinner + disabled state — can be generalized
- `useActionState` across all forms: Already provides `_isPending` variable (currently unused in most forms)
- Zod already in project for server-side validation in `actions.ts`

### Established Patterns
- Error display: Inline `aria-live="polite"` region with error icon + red text (login page pattern)
- Button styling: `rounded-xl bg-gradient-to-r from-accent to-accent-light` with shadow and hover scale
- Disabled state: `disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100`
- Server action errors return `string | undefined` (most forms) or `{ error: string }` (selectPlan)
- Color system: Tailwind CSS 4 with custom theme variables in `globals.css`

### Integration Points
- `app/layout.tsx`: Toaster component from sonner needs to be added here
- `app/providers/theme-provider.tsx`: Toast theme should respect dark mode context
- `app/add/add-card-form.tsx`: Needs validation, loading states, and toast integration
- `app/card/[id]/edit/edit-form.tsx`: Same as add form
- `app/register/page.tsx`: Needs field-level validation
- `app/login/page.tsx`: Already has loading state, needs field-level validation
- `app/subscribe/page.tsx`: Needs loading state on action buttons
- `app/components/BottomNav.tsx`: Toast positioning must account for this

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 02-ux-quality-and-error-handling*
*Context gathered: 2026-02-28*
