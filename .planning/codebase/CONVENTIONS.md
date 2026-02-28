# Coding Conventions

**Analysis Date:** 2026-02-28

## Naming Patterns

**Files:**
- React page components: `page.tsx` (Next.js App Router convention)
- Client components: kebab-case descriptive names, e.g. `add-card-form.tsx`, `dark-mode-toggle.tsx`
- Shared components under `components/`: kebab-case, e.g. `logo-picker.tsx`
- Utility modules: kebab-case, e.g. `color-utils.ts`, `image-utils.ts`
- Root-level singletons: lowercase, e.g. `auth.ts`, `auth.config.ts`, `middleware.ts`
- Components in `app/components/`: PascalCase file names, e.g. `Barcode.tsx`, `BottomNav.tsx`

**Functions:**
- Exported functions: camelCase, e.g. `createCard`, `updateLastUsed`, `searchLogos`
- React components: PascalCase, e.g. `AddCardForm`, `LogoPicker`, `SubmitButton`
- Helper/utility functions: camelCase, e.g. `rgbToHsl`, `generateLightModeColor`, `formatRelativeTime`
- Async arrow functions as `const`: e.g. `export const preprocessImage = async (file: File): Promise<...> => {...}`
- Named async functions for Server Actions: e.g. `export async function createCard(...)`

**Variables:**
- camelCase throughout: `barcodeValue`, `colorLight`, `selectedLogo`, `isDarkMode`
- Boolean flags prefixed with `is`/`has`: `isScanning`, `isLoading`, `hasCustomColors`, `hasSelectedPlan`
- Constants: camelCase (not SCREAMING_SNAKE_CASE), e.g. `const MAX_FILE_SIZE = 5 * 1024 * 1024`

**Types:**
- Interfaces for component props: `interface LogoPickerProps {...}`, `interface LogoResult {...}`
- Type aliases for simple shapes: `type Theme = 'light' | 'dark'`, `type ClearbitSuggestion = {...}`
- Prisma-generated enums used directly: `SubscriptionStatus`, `SubscriptionTier`
- Generic type extensions via `declare module` augmentation in `types/next-auth.d.ts`

## Code Style

**Formatting:**
- No Prettier config detected — formatting is manual/editor-managed
- 4-space indentation throughout (consistent in all `.ts`/`.tsx` files)
- Single quotes for imports: `import { auth } from '@/auth'`
- No trailing semicolons in some files, but present in most — inconsistent

**Linting:**
- ESLint with `eslint-config-next/core-web-vitals` and `eslint-config-next/typescript`
- Config at `eslint.config.mjs`
- `/* eslint-disable @next/next/no-img-element */` used where `<img>` tags are intentional
- `// eslint-disable-next-line react-hooks/exhaustive-deps` used for intentional dependency omissions

## Import Organization

**Order (observed pattern):**
1. React/Next.js framework imports: `import { useEffect, useRef } from 'react'`
2. Third-party library imports: `import bwipjs from 'bwip-js'`
3. Internal path-aliased imports: `import { auth } from '@/auth'`, `import { prisma } from '@/lib/prisma'`
4. Relative internal imports: `import LogoPicker from '@/components/logo-picker'`

**Path Aliases:**
- `@/*` maps to project root (configured in `tsconfig.json`)
- Used consistently throughout: `@/auth`, `@/lib/prisma`, `@/lib/stripe`, `@/app/lib/actions`, `@/components/logo-picker`

## Server vs Client Component Directives

**Client Components:**
- Marked with `'use client'` at top of file
- Used when: hooks (`useState`, `useEffect`, `useRef`), event handlers, browser APIs
- Examples: `app/add/add-card-form.tsx`, `app/components/Barcode.tsx`, `components/logo-picker.tsx`

**Server Actions:**
- Marked with `'use server'` at top of file
- `app/lib/actions.ts` is the sole server actions module
- Inline server actions used in `app/settings/page.tsx` for sign-out form

**Server Components (default):**
- Page components without any directive are server components
- Fetch data directly via `prisma` and `auth()`: `app/dashboard/page.tsx`, `app/settings/page.tsx`

## Error Handling

**Server Actions pattern — return string errors:**
```typescript
export async function createCard(prevState: string | undefined, formData: FormData) {
    if (!session?.user?.email) {
        return 'Not authenticated'
    }
    // ...
    return 'User not found'
}
```

**selectPlan returns object errors:**
```typescript
export async function selectPlan(prevState: { error: string }, formData: FormData) {
    if (!session?.user?.email) {
        return { error: 'Not authenticated' }
    }
}
```

**Best-effort operations swallow errors silently:**
```typescript
try {
    await prisma.brandLogo.upsert({ ... })
} catch {
    // Logo caching is best-effort
}
```

**API routes use try/catch with NextResponse:**
```typescript
try {
    // ...
    return NextResponse.json({ received: true })
} catch (error) {
    console.error('Webhook error:', error)
    return NextResponse.json({ error: 'Webhook handler failed' }, { status: 500 })
}
```

**Auth errors use instanceof checks:**
```typescript
if (error instanceof AuthError) {
    switch (error.type) {
        case 'CredentialsSignin':
            return 'Invalid credentials.'
    }
}
throw error  // Re-throw non-auth errors
```

**Redirect/throw pattern (Next.js):**
- `redirect()` throws internally in Next.js — never caught, always re-thrown
- Pattern: guard with early `return`, call `redirect()` at end of success path

## Validation

**Zod schemas defined inline at point of use:**
```typescript
const parsed = z.object({
    email: z.string().email(),
    password: z.string().min(6),
}).safeParse({ email, password })

if (!parsed.success) {
    return 'Invalid fields'
}
```

**FormData extraction with type assertion:**
```typescript
const retailer = formData.get('retailer') as string
const imageFile = formData.get('image') as File
```

## Logging

**Framework:** `console` (no structured logging library)

**Patterns:**
- `console.error(...)` for actual errors and failed operations
- `console.log(...)` for debug/informational messages (present in client barcode scanning flow)
- `console.warn(...)` for degraded but non-fatal situations
- Webhook handler logs every event type: `console.log('Received webhook event:', event.type)`

## Comments

**When to Comment:**
- JSDoc-style `/** ... */` block comments on utility functions in `app/lib/color-utils.ts` and `app/lib/image-utils.ts`
- Inline `//` comments to explain non-obvious business logic
- `// Continue without X rather than failing completely` pattern for best-effort operations
- Section markers in long JSX: `{/* Scan Status Messages */}`, `{/* Image Preview */}`

## Function Design

**Size:** Large functions are accepted — `createCard` and `updateCard` in `app/lib/actions.ts` are 80-90 lines each with duplicated image upload logic

**Parameters:** Server Actions use `(prevState, formData: FormData)` signature for `useFormState` compatibility. Regular functions use typed params.

**Return Values:**
- Server actions return `string | undefined` (error message or nothing on success) or `{ error: string }` object
- Utility functions return typed values or `null` on failure: `Promise<{ colorLight: string; colorDark: string } | null>`
- API routes return `NextResponse.json(...)`

## Class Usage

**Service class pattern** used in `lib/stripe.ts`:
```typescript
export class SubscriptionService {
    static async createOrGetCustomer(userId: string, email: string) { ... }
    static async createCheckoutSession(...) { ... }
    // JSDoc comment on each static method
}
```
Only `SubscriptionService` uses a class. All other logic uses plain functions.

## Module Design

**Exports:**
- Named exports for utilities and actions: `export async function createCard`
- Default exports for React components: `export default function AddCardForm`
- Named exports for service classes: `export class SubscriptionService`
- Mixed in `auth.ts`: named destructured exports `export const { handlers, auth, signIn, signOut } = NextAuth(...)`

**Barrel Files:** Not used. Import directly from source files.

## Prisma Usage Patterns

**Singleton client** at `lib/prisma.ts` — global cache to avoid exhausting connections in dev:
```typescript
const globalForPrisma = globalThis as unknown as { prisma: PrismaClient }
export const prisma = globalForPrisma.prisma || new PrismaClient()
if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma
```

**Select projection** used to minimize data returned:
```typescript
await prisma.user.findUnique({
    where: { email: session.user.email },
    select: { id: true }
})
```

**Include for relations:**
```typescript
await prisma.card.findUnique({
    where: { id },
    include: { user: true }
})
```

---

*Convention analysis: 2026-02-28*
