# Phase 2: UX Quality and Error Handling - Research

**Researched:** 2026-02-28
**Domain:** React 19 error handling patterns, sonner toast, Zod v4 client-side validation, camera API errors
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **BUG-04 (Barcode render fallback):** When bwip-js fails to render, replace the canvas area with a styled fallback showing the raw barcode number and a copy button. Fallback occupies the same space as the barcode canvas — inline replacement, not a separate card.
- **UX-01 (Scan error presentation):** Permission denied / camera not found: replace the camera view with an error state (icon + message + action). Decode failure: overlay on the camera feed with retry option. Categorize errors into: permission denied, camera not found, decode failure — each with specific remediation text.
- **UX-05 (Toast library):** Use sonner library as specified in requirements.

### Claude's Discretion
- Copy-to-clipboard confirmation: toast vs inline checkmark
- UX-02 (Form validation): validation timing (blur, blur+change, or similar); error styling; whether to use shared Zod schemas or plain client-side checks; which card form fields need validation beyond 'required'
- UX-04 (Loading states): spinner + text pattern; disabled behavior during pending; scope of actions needing loading states; whether to create a shared SubmitButton component
- UX-05 (Toast): position (mobile-first, BottomNav present); toast vs inline error split; auto-dismiss duration; theme customization level
- UX-03 (Empty state): whether existing empty state meets the requirement or needs enhancement
- Visual styling of all error states and loading indicators
- Component architecture (shared vs inline)

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| BUG-04 | Barcode component shows error state instead of blank when bwip-js render fails (fallback: raw number + copy button) | bwip-js throws synchronously on error; try/catch pattern in useEffect; Clipboard API for copy button |
| UX-01 | Categorized barcode scan error messages with actionable remediation text (permission denied, camera not found, decode failure) | useZxing onError callback; error.name discrimination (NotAllowedError, NotFoundError); useBarcodeScanner hook already has scanStatus state |
| UX-02 | Inline client-side form validation on register, login, and card forms (validate on blur, field-level errors) | Zod v4 already in project; client-side parse pattern; blur event handlers; existing controlled inputs |
| UX-03 | Empty state for dashboard with no cards (illustration + "Add your first card" CTA) | Dashboard already has basic empty state — may need icon/copy enhancement only |
| UX-04 | Loading/pending states on all Server Action buttons (spinner or "Saving...") | useFormStatus pattern already in LoginButton, SubmitButton — needs generalization to shared component; _isPending from useActionState already available |
| UX-05 | Toast notification system for non-blocking errors (image upload failures, network errors) via sonner | sonner 2.0.x; Toaster in layout.tsx; theme prop tied to ThemeContext; position above BottomNav |
</phase_requirements>

---

## Summary

Phase 2 is a pure polish phase — no new server actions, no schema changes, no new routes. All work is client-side UI enhancement layered on top of the existing codebase. The project uses React 19 (`useActionState`, `useFormStatus`), Tailwind CSS 4 with custom CSS variables, and Zod v4 (already installed). The main new library addition is `sonner` for toast notifications.

The existing codebase already has the structural foundations: `useBarcodeScanner` hook with `scanStatus` state, `LoginButton`/`SubmitButton` patterns with `useFormStatus`, inline `aria-live` error regions, and a basic empty state in the dashboard. Phase 2 enhances these foundations rather than replacing them.

The most complex work is: (1) extending `useBarcodeScanner` to expose categorized camera error types from the `useZxing` `onError` callback, and (2) adding client-side blur validation across four forms using Zod schemas that mirror the server-side validation already in `actions.ts`. The `sonner` integration is straightforward — one `<Toaster />` in `layout.tsx` with theme driven from `ThemeContext`.

**Primary recommendation:** Use Zod v4 directly for client-side validation (no `react-hook-form` needed — forms are already controlled inputs with `useActionState`), sonner 2.x for toasts, and extend `useBarcodeScanner` to categorize errors by `error.name` from the `onError` callback of `useZxing`.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| sonner | ^2.0.7 | Toast notification system | Specified in requirements; lightweight, opinionated, no state needed to trigger toasts |
| zod | ^4.1.13 (already installed) | Client-side form schema validation | Already in project for server-side; same schemas reusable on client |
| react (useFormStatus) | 19.2.1 (already installed) | Pending state for submit buttons | Built-in React 19 hook; existing LoginButton/SubmitButton pattern |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| navigator.clipboard | Browser API (no install) | Copy barcode to clipboard | BUG-04 copy button fallback |
| useZxing (react-zxing) | ^1.1.3 (already installed) | Camera scan errors via onError callback | UX-01 — extend existing useBarcodeScanner hook |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Zod v4 direct parse | react-hook-form + zodResolver | react-hook-form adds ~12KB, but forms are already controlled with useActionState — adding RHF creates two competing state systems |
| Manual blur validation | Formik | Formik is heavier and not aligned with Server Actions pattern |
| sonner | react-hot-toast | User explicitly chose sonner in requirements |
| navigator.clipboard | react-copy-to-clipboard package | No need for extra package; Clipboard API is supported in all modern browsers on HTTPS |

**Installation:**
```bash
npm install sonner
```
(Zod, react-zxing, react, and react-dom are already installed)

---

## Architecture Patterns

### Recommended Project Structure
```
app/
├── components/
│   ├── Barcode.tsx               # Add error state with copy fallback (BUG-04)
│   ├── SubmitButton.tsx          # NEW: Shared submit button with useFormStatus (UX-04)
│   └── BottomNav.tsx             # Unchanged
├── hooks/
│   └── useBarcodeScanner.ts      # Extend: add ScanErrorType, onError plumbing (UX-01)
├── lib/
│   ├── actions.ts                # Unchanged
│   └── validation.ts             # NEW: Shared Zod client schemas (UX-02)
├── login/page.tsx                # Add blur validation (UX-02)
├── register/page.tsx             # Add blur validation (UX-02)
├── add/add-card-form.tsx         # Add blur validation + camera errors (UX-01, UX-02)
├── card/[id]/edit/edit-form.tsx  # Add blur validation + camera errors (UX-01, UX-02)
├── dashboard/page.tsx            # Evaluate/enhance empty state (UX-03)
└── layout.tsx                    # Add <Toaster /> (UX-05)
```

### Pattern 1: Sonner Toaster Integration (dark mode without next-themes)
**What:** Place `<Toaster />` in `app/layout.tsx` body. Theme driven from ThemeContext using `useTheme()`. Position `top-center` to avoid BottomNav at the bottom.
**When to use:** Non-blocking error notifications for image upload failures, network errors, and copy confirmations.

The project uses `.dark` class on `<html>` toggled by `ThemeProvider`, not `next-themes`. Sonner supports this directly:

```typescript
// Source: https://github.com/emilkowalski/sonner
// app/components/ToasterWithTheme.tsx
'use client'
import { Toaster } from 'sonner'
import { useTheme } from '@/app/providers/theme-provider'

export function ToasterWithTheme() {
    const { theme } = useTheme()
    return (
        <Toaster
            theme={theme}
            position="top-center"
            richColors
            offset={16}
            toastOptions={{
                duration: 4000,
                classNames: {
                    toast: 'rounded-xl text-sm',
                },
            }}
        />
    )
}
```

Then in `app/layout.tsx` (inside `<ThemeProvider>`):
```typescript
<ThemeProvider initialTheme={initialTheme}>
    {children}
    <BottomNav />
    <ToasterWithTheme />
</ThemeProvider>
```

**Why `top-center`:** BottomNav is fixed at the bottom and occupies ~64px + safe area. Placing toasts at the bottom would collide with navigation. `top-center` is conventional for mobile PWAs where bottom nav exists.

### Pattern 2: Barcode Component Error State (BUG-04)
**What:** Stateful `Barcode` component that tracks render success/failure. On failure, shows a styled fallback with the raw value and copy button in the same dimensions as the canvas.

```typescript
// Source: bwip-js docs (https://github.com/metafloor/bwip-js/wiki/Methods-Reference)
'use client'
import { useEffect, useRef, useState } from 'react'
import bwipjs from 'bwip-js'

type BarcodeState = 'idle' | 'success' | 'error'

export default function Barcode({ value, format }: { value: string; format: string }) {
    const canvasRef = useRef<HTMLCanvasElement>(null)
    const [state, setState] = useState<BarcodeState>('idle')
    const [copied, setCopied] = useState(false)

    useEffect(() => {
        if (!canvasRef.current || !value || !format) return
        try {
            bwipjs.toCanvas(canvasRef.current, {
                bcid: format,
                text: value,
                scale: 3,
                height: 10,
                includetext: false,
                textxalign: 'center',
            })
            setState('success')
        } catch {
            setState('error')
        }
    }, [value, format])

    const handleCopy = async () => {
        try {
            await navigator.clipboard.writeText(value)
            setCopied(true)
            setTimeout(() => setCopied(false), 2000)
        } catch {
            // clipboard unavailable — inline fallback only
        }
    }

    if (state === 'error') {
        return (
            <div className="flex flex-col items-center gap-2 p-4 bg-warning/10 border border-warning/20 rounded-xl">
                <p className="text-xs text-muted">Barcode preview unavailable</p>
                <p className="font-mono text-sm font-medium text-primary">{value}</p>
                <button
                    type="button"
                    onClick={handleCopy}
                    className="text-xs text-accent hover:text-accent-dark transition-colors flex items-center gap-1"
                >
                    {copied ? '✓ Copied' : 'Copy number'}
                </button>
            </div>
        )
    }

    return <canvas ref={canvasRef} className="max-w-full" />
}
```

**Key insight:** `bwipjs.toCanvas()` is synchronous and throws on error (string or Error object). Wrap in try/catch in useEffect and track state.

### Pattern 3: Categorized Camera Scan Errors (UX-01)
**What:** Extend `ScanErrorType` in `useBarcodeScanner` to distinguish three cases. Hook `useZxing`'s `onError` callback is called with a browser `DOMException`. Discriminate by `error.name`.

```typescript
// Source: react-zxing npm docs + MDN DOMException names
export type ScanErrorType =
    | 'permission-denied'   // NotAllowedError — user blocked camera
    | 'camera-not-found'    // NotFoundError — no camera device
    | 'decode-failure'      // Image upload found no barcode

export type ScanStatus = 'idle' | 'scanning' | 'success' | 'error'

// In useBarcodeScanner hook, extend the useZxing call:
const { ref } = useZxing({
    onResult(result) { /* ... existing */ },
    onError(error) {
        if (error.name === 'NotAllowedError') {
            setScanErrorType('permission-denied')
        } else if (error.name === 'NotFoundError') {
            setScanErrorType('camera-not-found')
        }
        setScanStatus('error')
        setIsScanning(false)
    },
    paused: !isScanning,
})
```

**Remediation text per error type:**
- `permission-denied`: "Camera access was blocked. To scan, allow camera access in your browser settings, then try again."
- `camera-not-found`: "No camera detected on this device. Use 'Upload Photo' to scan from an image, or enter the barcode number manually."
- `decode-failure`: "No barcode found in this image. Try a clearer photo, or enter the barcode number manually."

**IMPORTANT CAVEAT:** The `react-zxing` library's `onError` callback may not always fire for `NotAllowedError`/`NotFoundError` — these errors can occur before decoder initialization and may not propagate. The fallback is to also use `navigator.permissions.query({ name: 'camera' })` to check permission state proactively when the scan button is clicked. (LOW confidence that `onError` always fires for permission errors — test this during implementation.)

### Pattern 4: Blur Validation with Zod v4 (UX-02)
**What:** Client-side field validation triggered on blur. Keep forms as-is (controlled inputs + `useActionState`). Add a `fieldErrors` state map. On blur, run Zod `.safeParse()` for that field and update errors. Clear field error on next change event.

```typescript
// Source: Zod v4 docs (https://zod.dev)
// app/lib/validation.ts — shared client schemas
import { z } from 'zod'

export const loginSchema = z.object({
    email: z.string().email('Enter a valid email address'),
    password: z.string().min(1, 'Password is required'),
})

export const registerSchema = z.object({
    email: z.string().email('Enter a valid email address'),
    password: z.string().min(6, 'Password must be at least 6 characters'),
})

export const cardSchema = z.object({
    retailer: z.string().min(1, 'Retailer name is required'),
    barcodeValue: z.string().optional(),
    note: z.string().optional(),
})
```

Validation in component:
```typescript
const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

const validateField = (name: string, value: string) => {
    const result = schema.shape[name]?.safeParse(value)
    if (result && !result.success) {
        setFieldErrors(prev => ({ ...prev, [name]: result.error.issues[0].message }))
    } else {
        setFieldErrors(prev => { const next = {...prev}; delete next[name]; return next })
    }
}

// On input:
<input
    onBlur={(e) => validateField('email', e.target.value)}
    onChange={(e) => {
        setEmail(e.target.value)
        if (fieldErrors.email) validateField('email', e.target.value)
    }}
/>
{fieldErrors.email && (
    <p className="mt-1 text-xs text-error" role="alert">{fieldErrors.email}</p>
)}
```

**Input border error state:** When a field has an error, add `border-error focus:ring-error/20` to the input className. Existing clean class is `border-border focus:border-accent focus:ring-accent/20`.

### Pattern 5: Shared SubmitButton Component (UX-04)
**What:** Extract the common submit button pattern into a reusable `SubmitButton` component that accepts `label` and `pendingLabel` props.

```typescript
// app/components/SubmitButton.tsx
'use client'
import { useFormStatus } from 'react-dom'

interface SubmitButtonProps {
    label: string
    pendingLabel?: string
    className?: string
}

export function SubmitButton({ label, pendingLabel, className }: SubmitButtonProps) {
    const { pending } = useFormStatus()
    const displayLabel = pendingLabel ?? `${label.split(' ')[0]}ing...`

    return (
        <button
            type="submit"
            disabled={pending}
            className={`flex w-full justify-center items-center gap-2 rounded-xl bg-gradient-to-r from-accent to-accent-light px-4 py-3.5 text-sm font-semibold text-white shadow-lg shadow-accent/25 hover:shadow-accent/40 hover:scale-[1.02] focus:outline-none focus:ring-2 focus:ring-accent focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100 transition-all ${className ?? ''}`}
        >
            {pending ? (
                <>
                    <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    {pendingLabel ?? 'Saving...'}
                </>
            ) : label}
        </button>
    )
}
```

### Anti-Patterns to Avoid
- **Do not add `react-hook-form`:** Forms are already controlled inputs driven by `useActionState`. Adding RHF creates two competing state systems. Use Zod directly with manual `onBlur` handlers.
- **Do not place `<Toaster />` outside `<ThemeProvider>`:** It needs access to ThemeContext for dark mode theme prop. Wrap it as a client component inside ThemeProvider.
- **Do not use `theme="system"` on Toaster:** The app manages its own theme via ThemeContext/CSS `.dark` class. Pass `theme={theme}` directly from `useTheme()`.
- **Do not dispatch toasts for form submission errors that are already shown inline:** Inline `aria-live` regions handle form errors. Use toasts only for non-blocking background failures (image upload, network errors).
- **Do not add `position="bottom-center"` to Toaster:** BottomNav is fixed at bottom with ~80px height. Toasts would be hidden behind it.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Toast notifications | Custom modal/alert system | sonner | Accessibility (aria-live), animation, stacking, dismiss handling — complex to get right |
| Clipboard copy | execCommand fallback | navigator.clipboard.writeText | execCommand is deprecated; Clipboard API handles permissions correctly |
| Camera error discrimination | Custom permission detection | error.name from DOMException | Browser error names are standardized (NotAllowedError, NotFoundError) |
| Barcode error detection | Custom canvas validity check | try/catch around bwipjs.toCanvas | bwip-js throws synchronously with descriptive error — no need to inspect canvas |

**Key insight:** This phase has minimal "don't hand-roll" surface because the problems are fundamentally UI pattern work, not complex library integration. The main value is in following the existing project's established patterns correctly.

---

## Common Pitfalls

### Pitfall 1: Zod v4 Schema Import Path and API Changes
**What goes wrong:** Code written for Zod v3 uses `z.string().email()` which was changed to `z.email()` in v4. Project is on Zod 4.1.13.
**Why it happens:** Zod v4 promoted string format validators to top-level. However, `z.string().email()` still works in v4 (it was not removed, just supplemented). The project's existing `actions.ts` already uses `z.string().email()` successfully. No migration needed for client schemas.
**How to avoid:** Continue using `z.string().email()` pattern from `actions.ts`. Import from `'zod'` (not `'zod/v4'`). Avoid `z.string().uuid()` — use `z.guid()` in v4 if UUID validation is needed.
**Warning signs:** TypeScript errors on `z.object()` or `.safeParse()` would indicate import issues.

### Pitfall 2: useZxing onError May Not Fire for Camera Errors
**What goes wrong:** `NotAllowedError` and `NotFoundError` from `getUserMedia()` may not propagate to the `onError` callback of `useZxing` because they occur before decoder initialization.
**Why it happens:** `react-zxing` wraps ZXing's browser module; camera permission errors occur at the `getUserMedia` stage before ZXing's decoder is active.
**How to avoid:** In addition to `onError`, proactively check `navigator.permissions.query({ name: 'camera' })` when the scan button is clicked. Set scan error state before attempting to start the scanner if permission is already denied.
**Warning signs:** Camera permission denied but no error state shown; `isScanning` stays true.

### Pitfall 3: Toaster Dark Mode Flash
**What goes wrong:** On initial page load, toast appears in wrong theme because `ThemeProvider` reads initial theme from server but the `ToasterWithTheme` client component briefly shows default light theme.
**Why it happens:** `ThemeProvider` receives `initialTheme` from the server and sets it correctly, but if the `Toaster` renders before the ThemeContext hydrates, it defaults to `theme="light"`.
**How to avoid:** Wrap `ToasterWithTheme` inside `ThemeProvider` (which the layout already does). Since ThemeProvider initializes with `initialTheme` passed from server, there should be no flash. Test with dark mode default.
**Warning signs:** Toast theme doesn't match page theme on first render.

### Pitfall 4: Field Errors Persisting After Successful Server Action
**What goes wrong:** Client-side field errors (from blur validation) persist on screen after the form is submitted successfully.
**Why it happens:** `useActionState` returns the latest state but doesn't automatically clear local `fieldErrors` state.
**How to avoid:** Clear `fieldErrors` on form reset or when the server action returns a success indicator. For register page, already handles success via `useEffect` watching `errorMessage === 'success'` — add `setFieldErrors({})` there.
**Warning signs:** Red error borders remain after successful submit.

### Pitfall 5: bwip-js Error Type is String or Error
**What goes wrong:** Treating `bwip-js` catch block `e` as an `Error` object when it may be a string.
**Why it happens:** bwip-js throws either a `string` or an `Error` object depending on error type (BWIPP vs JavaScript runtime errors).
**How to avoid:** Handle both: `const message = typeof e === 'string' ? e : (e as Error).message`. For the UI fallback, the specific error type doesn't matter — just show the fallback.
**Warning signs:** `e.message` throws `TypeError: Cannot read property 'message' of string`.

### Pitfall 6: Copy Button Requires User Gesture
**What goes wrong:** `navigator.clipboard.writeText()` fails with `NotAllowedError` if called outside a user-initiated event.
**Why it happens:** Clipboard API requires a user gesture (click, tap) and HTTPS context.
**How to avoid:** Only call `navigator.clipboard.writeText()` inside a button `onClick` handler (which is already the plan). Works on localhost in dev mode.
**Warning signs:** Copy silently fails on HTTP or non-gesture contexts.

---

## Code Examples

### Sonner Toast Usage (from anywhere in the app)
```typescript
// Source: https://github.com/emilkowalski/sonner
import { toast } from 'sonner'

// In an event handler or after an async operation:
toast.error('Failed to upload image. Please try again.')
toast.success('Card saved successfully.')
toast('Barcode number copied.')  // neutral

// With options:
toast.error('Upload failed', {
    description: 'Only JPG, PNG, and WebP images are accepted.',
    duration: 5000,
})
```

### Zod v4 safeParse for Blur Validation
```typescript
// Source: https://zod.dev
import { z } from 'zod'

const emailSchema = z.string().email('Enter a valid email address')
const result = emailSchema.safeParse(value)
if (!result.success) {
    const message = result.error.issues[0].message  // Zod v4 uses .issues
}
```

### Camera Scan Error State Rendering
```typescript
// Source: research pattern based on react-zxing + MDN DOMException
{isScanning && scanErrorType === 'permission-denied' && (
    <div className="relative aspect-video w-full overflow-hidden rounded-xl bg-error/10 border border-error/20 flex flex-col items-center justify-center gap-3 p-6">
        {/* camera-blocked icon */}
        <p className="text-sm font-medium text-primary text-center">
            Camera access was blocked
        </p>
        <p className="text-xs text-muted text-center">
            Allow camera access in your browser settings, then tap &quot;Scan&quot; again
        </p>
        <button type="button" onClick={() => { setIsScanning(false); setScanErrorType(null) }}
            className="text-sm text-accent hover:text-accent-dark transition-colors">
            Dismiss
        </button>
    </div>
)}
```

### Input Error State Styling (Tailwind CSS 4 pattern)
```typescript
// Existing clean state:
// "block w-full rounded-xl border border-border ... focus:border-accent focus:ring-2 focus:ring-accent/20"

// Error state — add these classes:
const inputClass = `block w-full rounded-xl border px-4 py-3 text-primary placeholder-muted shadow-sm focus:outline-none focus:ring-2 transition-all text-sm ${
    fieldErrors.email
        ? 'border-error focus:border-error focus:ring-error/20'
        : 'border-border dark:border-border focus:border-accent focus:ring-accent/20'
} bg-background dark:bg-surface-elevated`
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `useFormState` (react-dom) | `useActionState` (react) | React 19 (project already migrated) | Clean import from 'react'; isPending is third return value |
| `document.execCommand('copy')` | `navigator.clipboard.writeText()` | ~2020, widespread support by 2023 | Promise-based, secure context required |
| Custom spinner components | Inline SVG `animate-spin` | Tailwind CSS convention | Already used in project's LoginButton/SubmitButton |
| `toast.error()` with inline `message` only | `toast.error(title, { description })` | sonner 1.x | Can show title + description for richer context |

**Deprecated/outdated:**
- `useFormState` from `react-dom`: replaced by `useActionState` from `react` — already done in Phase 1
- `document.execCommand('copy')`: MDN marks as obsolete — use Clipboard API

---

## Open Questions

1. **Does useZxing onError reliably fire for NotAllowedError/NotFoundError?**
   - What we know: The react-zxing library has a known issue where camera-level errors may not propagate to the onError callback because they occur before decoder initialization
   - What's unclear: Whether version 1.1.3 (installed) has this issue fixed
   - Recommendation: During implementation, test by denying camera permission and verifying onError fires. If it does not, add proactive `navigator.permissions.query({ name: 'camera' })` check before calling `setIsScanning(true)`. This is LOW confidence.

2. **Does the existing dashboard empty state fully satisfy UX-03?**
   - What we know: Dashboard has an icon (`CreditCard` SVG), "No cards yet" heading, description text, and "Add First Card" gradient button
   - What's unclear: The success criterion says "illustration and 'Add your first card' call-to-action" — the existing implementation has an icon (not illustration), the CTA says "Add First Card" (not "Add your first card")
   - Recommendation: The existing empty state is substantively correct. Minor text/visual enhancement (change button text, possibly add a second decoration element) should satisfy UX-03 without significant new work.

3. **Zod v4 `.issues` vs `.errors` terminology**
   - What we know: Zod v4 uses `.issues` array on ZodError (not `.errors`)
   - What's unclear: Whether project's existing `actions.ts` usage (`.safeParse()` then `!parsed.success`) needs updating
   - Recommendation: The existing code in `actions.ts` only checks `parsed.success` without accessing error details — no change needed there. New client validation code should use `result.error.issues[0].message`.

---

## Sources

### Primary (HIGH confidence)
- [sonner GitHub (emilkowalski/sonner)](https://github.com/emilkowalski/sonner) — Toaster props, theme options, position, richColors, toastOptions
- [bwip-js wiki Methods Reference](https://github.com/metafloor/bwip-js/wiki/Methods-Reference) — toCanvas synchronous throws on error, error type (string or Error)
- [Zod v4 docs](https://zod.dev) — .safeParse(), .issues, z.string().email() compatibility
- Project source files read directly: `useBarcodeScanner.ts`, `Barcode.tsx`, `login/page.tsx`, `register/page.tsx`, `add/add-card-form.tsx`, `edit-form.tsx`, `layout.tsx`, `theme-provider.tsx`, `globals.css`, `package.json`

### Secondary (MEDIUM confidence)
- [MDN DOMException names](https://developer.mozilla.org/en-US/docs/Web/API/DOMException) — NotAllowedError, NotFoundError error names for camera errors
- [MDN Clipboard API](https://developer.mozilla.org/en-US/docs/Web/API/Clipboard_API) — navigator.clipboard.writeText, HTTPS requirement, user gesture requirement
- [sonner npm page](https://www.npmjs.com/package/sonner) — version 2.0.7 confirmed latest

### Tertiary (LOW confidence)
- react-zxing `onError` callback reliability for camera permission errors — based on GitHub issues from `@zxing/ngx-scanner` and `react-zxing` — NOT verified against 1.1.3 source. Test during implementation.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — sonner is specified in requirements; Zod/React 19 already in project; no new library unknowns
- Architecture: HIGH — all patterns are straightforward extensions of existing code in the project
- Pitfalls: MEDIUM — bwip-js error type and Zod v4 confirmed; useZxing onError reliability is LOW confidence

**Research date:** 2026-02-28
**Valid until:** 2026-03-30 (stable libraries; sonner and Zod v4 unlikely to break in 30 days)
