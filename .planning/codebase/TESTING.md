# Testing Patterns

**Analysis Date:** 2026-02-28

## Test Framework

**Runner:** None configured

No test framework is installed or configured in this project. There are no Jest, Vitest, Playwright, or Cypress dependencies in `package.json`. There are no test configuration files (`jest.config.*`, `vitest.config.*`, `playwright.config.*`).

**Test Files:** Zero test files exist in the codebase. No `*.test.*` or `*.spec.*` files found anywhere.

**Run Commands:**
```bash
# No test commands exist
# package.json scripts: dev, build, start, lint, postinstall only
```

## Test File Organization

**Location:** Not applicable — no tests exist

**Naming:** No conventions established

## Test Structure

No test structure exists to document.

## Mocking

No mocking patterns established.

## Fixtures and Factories

No fixtures or factories established.

## Coverage

**Requirements:** None enforced

**Coverage tooling:** None installed

## Test Types

**Unit Tests:** Not present

**Integration Tests:** Not present

**E2E Tests:** Not present

## Testing Guidance for Future Implementation

Given the codebase structure, the following would be the appropriate testing approach when tests are added:

### Recommended Framework

**Vitest** (preferred for Next.js App Router projects):
```bash
npm install -D vitest @vitejs/plugin-react jsdom @testing-library/react @testing-library/user-event
```

**Or Jest** with Next.js preset:
```bash
npm install -D jest jest-environment-jsdom @testing-library/react @testing-library/user-event
```

### Priority Test Targets

**High-value unit test targets (pure functions, no side effects):**

1. `app/lib/color-utils.ts` — All functions are pure and deterministic:
   - `rgbToHsl(r, g, b)` — color space conversion
   - `hslToRgb(h, s, l)` — color space conversion
   - `rgbToHex(r, g, b)` — formatting
   - `shouldFilterColor(r, g, b)` — filtering logic
   - `generateLightModeColor(r, g, b)` — color derivation
   - `generateDarkModeColor(r, g, b)` — color derivation

2. `app/lib/image-utils.ts` — `getRotatedCanvases` logic (canvas-dependent, needs jsdom or mock)

3. `lib/stripe.ts` — `SubscriptionService` static methods (would need Stripe and Prisma mocked)

**Server Actions in `app/lib/actions.ts`** require Prisma and auth mocking — integration-style tests more appropriate.

### Suggested Mock Pattern for Prisma

```typescript
// __mocks__/lib/prisma.ts
export const prisma = {
    user: {
        findUnique: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
    },
    card: {
        findMany: vi.fn(),
        findUnique: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
    },
    subscription: {
        findUnique: vi.fn(),
        create: vi.fn(),
        upsert: vi.fn(),
        update: vi.fn(),
    },
    brandLogo: {
        findUnique: vi.fn(),
        upsert: vi.fn(),
    },
}
```

### Suggested Mock Pattern for NextAuth

```typescript
vi.mock('@/auth', () => ({
    auth: vi.fn().mockResolvedValue({
        user: { email: 'test@example.com', id: 'user-123' }
    }),
    signIn: vi.fn(),
    signOut: vi.fn(),
}))
```

### Example Unit Test Structure (color-utils)

```typescript
import { describe, it, expect } from 'vitest'
import { rgbToHsl, shouldFilterColor, generateLightModeColor } from '@/app/lib/color-utils'

describe('rgbToHsl', () => {
    it('converts pure red correctly', () => {
        const [h, s, l] = rgbToHsl(255, 0, 0)
        expect(h).toBe(0)
        expect(s).toBe(100)
        expect(l).toBe(50)
    })
})

describe('shouldFilterColor', () => {
    it('filters out near-white colors', () => {
        expect(shouldFilterColor(250, 250, 250)).toBe(true)
    })

    it('filters out near-black colors', () => {
        expect(shouldFilterColor(5, 5, 5)).toBe(true)
    })

    it('keeps saturated brand colors', () => {
        expect(shouldFilterColor(220, 50, 50)).toBe(false)
    })
})
```

### Example Server Action Test Structure

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { register } from '@/app/lib/actions'

vi.mock('@/lib/prisma', () => ({ prisma: { ... } }))
vi.mock('@/auth', () => ({ signIn: vi.fn() }))

describe('register', () => {
    it('returns error for invalid email', async () => {
        const formData = new FormData()
        formData.set('email', 'not-an-email')
        formData.set('password', 'password123')
        const result = await register(undefined, formData)
        expect(result).toBe('Invalid fields')
    })
})
```

## Current State Summary

This project has **zero automated tests**. The entire application relies on manual testing. Any feature work should be accompanied by test setup as a prerequisite phase.

---

*Testing analysis: 2026-02-28*
