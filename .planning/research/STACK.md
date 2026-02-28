# Stack Research

**Domain:** Production hardening — loyalty card PWA (Next.js 16, React 19, self-hosted)
**Researched:** 2026-02-28
**Confidence:** MEDIUM-HIGH (verified via official docs, npm registry, and multiple corroborating sources)

---

## Recommended Stack

This is an additive stack. The existing framework (Next.js 16, React 19, TypeScript, Tailwind 4, Prisma, PostgreSQL, NextAuth v5, Stripe, ZXing, bwip-js) is not changed. Only new libraries needed for the four target areas are listed.

### Offline PWA

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| `@serwist/next` | `^9.2.3` | Next.js Workbox integration for service worker | Official Next.js docs recommend Serwist. Fork of Workbox specifically because Workbox development stagnated. v9+ supports both Webpack and Turbopack (separate quick-start guides). Actively maintained — v9.5.6 published February 2026. |
| `serwist` (dev dep) | `^9.5.6` | Service worker tooling / Workbox strategies | Required peer to `@serwist/next`. Provides `Serwist` class, `defaultCache`, `StaleWhileRevalidate`, and other caching strategies used in the `sw.ts` file. |
| `idb` | `^8.0.3` | IndexedDB wrapper for offline card storage | Jake Archibald's official IDB wrapper. 1.19kB brotli'd. Promise-based API over the raw IndexedDB. The right tool for storing structured card data offline. LocalStorage is synchronous and size-limited (~5MB) — not viable for card images and structured data. `idb` v8 is the current stable release. |

**Critical Serwist / Next.js 16 note (MEDIUM confidence):** Next.js 16 ships with Turbopack enabled by default in dev. Serwist's service worker compilation uses Webpack. The official Serwist docs provide a dedicated Turbopack quick-start guide distinct from the Webpack guide. You must either: (a) use `next build --webpack` for production builds, or (b) follow the Serwist Turbopack guide. Do not mix them. Disable Serwist in development (`disable: process.env.NODE_ENV === 'development'`) to avoid cache interference during dev.

### Security Hardening

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| `sharp` | `^0.34.5` | Image upload validation + sanitization | Two roles: (1) Validates uploads by attempting to read image metadata — if `sharp` throws, the file is not a valid image. (2) Re-encodes the image, stripping EXIF data and any embedded payloads. This is more secure than magic-bytes alone because it forces a full image decode. Next.js already recommends `sharp` for image optimization — adding it here is consistent. |
| `lru-cache` | `^11.x` | In-memory rate limiting store for auth endpoints | Self-hosted single-instance deployment (Docker Compose) means Redis is unnecessary overhead. An LRU Map is the standard pattern for in-memory rate limiting in single-server Next.js. The official Next.js rate-limit example uses `lru-cache`. Use `{ max: 500, ttl: 1000 * 60 * 15 }` (500 IPs, 15-minute window). **This is process-memory only — acceptable for single-Docker-instance.** |

**Do NOT use `@upstash/ratelimit`:** Requires a Redis instance (Upstash or self-hosted). This app is self-hosted single-server. Upstash rate limiting is designed for Vercel edge deployments. The added operational complexity of Redis for auth rate limiting on a single-instance app is not justified.

**Do NOT use `express-rate-limit`:** Not designed for Next.js Server Actions — it expects Express middleware context. Proxy IP detection also requires extra configuration Next.js doesn't expose cleanly.

**Do NOT use `file-type` v21:** Requires Node.js 20+. This project's Docker base image is `node:18-alpine`. `sharp` metadata validation covers the same security need without the Node.js version constraint.

### Performance

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| (no new library) | — | Cookie-based theme preference | Use `cookies()` from `next/headers` (built into Next.js). Write theme to a cookie via a Server Action. Read it in `app/layout.tsx` with `const cookieStore = await cookies()`. Eliminates the `auth()` + `prisma.user.findUnique` call on every page load for dark mode. Accepts the trade-off of dynamic rendering on layout — this is fine since auth pages are already dynamic. No external library needed. |
| (no new library) | — | JWT callback DB query optimization | Pure code change in `auth.config.ts`. Fix the `needsRefresh` condition so it only re-queries on `trigger === 'update'` (i.e., after an explicit subscription change), not on every token evaluation. No library needed — the fix is removing the over-eager condition. |

### Error Handling / UX

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| `sonner` | `^2.0.7` | Toast notifications for error and success states | Zero dependencies. Trusted by OpenAI, Adobe. shadcn/ui's official toast component. Native dark mode support — critical since this app has dark mode. Works from anywhere in the app without React state wiring. `react-hot-toast` is the alternative but has less ecosystem momentum in 2026. |

**Do NOT use `react-toastify`:** ~16KB gzipped vs. Sonner's near-zero. Feature-heavy but overkill for this use case.

---

## Supporting Libraries (No Install Needed — Already Available)

| Library | Already At | Why Relevant |
|---------|------------|-------------|
| `next/headers` `cookies()` | Built into Next.js 16 | Cookie-based theme — no new dep |
| `error.tsx` / `global-error.tsx` | Next.js App Router file convention | Error boundaries — no new dep |
| `zod` | `^4.1.13` (already installed) | File upload validation schema (MIME type allowlist, file size) — extend existing use |

---

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| `@serwist/next` | `@ducanh2912/next-pwa` | Simpler setup, less Turbopack risk. Choose if Serwist Turbopack guide proves too complex — same Workbox strategies underneath, slightly less flexible. |
| `sharp` for image validation | `magic-bytes.js` (v1.13.0) | If `sharp` native binaries cause issues in Docker Alpine. `magic-bytes.js` is pure JS, CJS-friendly, Node 18 compatible. Less security (doesn't re-encode), but valid for quick magic-byte checks. |
| `lru-cache` in-memory | Redis + `@upstash/ratelimit` | If the app ever scales to multiple Docker instances or adds a CDN layer — then distributed rate limiting is required. |
| `sonner` | `react-hot-toast` | If dark mode integration proves problematic or bundle size difference matters. |
| `idb` | Raw `indexedDB` API | Never. Raw IndexedDB API is unusable in practice. `idb` is maintained by a Google Chrome engineer and is the canonical wrapper. |

---

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `next-pwa` (shadowwalker) | Unmaintained, uses Webpack only, known Turbopack incompatibility | `@serwist/next` |
| `@upstash/ratelimit` | Requires Redis or Upstash cloud — unnecessary for self-hosted single instance | `lru-cache` in-process store |
| `express-rate-limit` | Not designed for Next.js Server Actions, proxy IP detection broken without Express | `lru-cache` custom implementation |
| `file-type` v21+ | Requires Node.js 20+; Docker base is `node:18-alpine` | `sharp` metadata validation |
| `localStorage` for theme | Causes flash of unstyled content (FOUC) on every page load | `cookies()` from `next/headers` |
| `next-themes` | Adds JS bundle for theme management that cookies handle natively | `cookies()` from `next/headers` |
| `workbox-*` directly | Serwist is the maintained fork; direct Workbox usage is stagnating | `serwist` + `@serwist/next` |

---

## Installation

```bash
# Offline PWA
npm install @serwist/next idb
npm install -D serwist

# Security: sharp for image validation (also needed by Next.js image optimization)
npm install sharp

# Error UX
npm install sonner

# Rate limiting: lru-cache (already a transitive dep in most Next.js projects, install explicitly)
npm install lru-cache
```

---

## Stack Patterns by Variant

**If Next.js 16 build uses Turbopack (default):**
- Follow the Serwist Turbopack quick-start at https://serwist.pages.dev/docs/next/turbo
- Add `--webpack` flag only to the `build` script if Turbopack guide is insufficient
- Do NOT disable Turbopack in dev just for Serwist — keep dev fast

**If Docker base is upgraded from Node 18 to Node 20+:**
- `file-type` v21 becomes available as an alternative to `sharp` for magic-bytes detection
- `file-type` v21 provides finer-grained MIME detection for non-image files

**If the app scales beyond single Docker instance:**
- Replace `lru-cache` rate limiting with `@upstash/ratelimit` + Redis
- Keep `sharp` validation — no change needed
- Keep Serwist — no change needed

---

## Version Compatibility

| Package | Compatible With | Notes |
|---------|-----------------|-------|
| `@serwist/next@^9.2.3` | Next.js 16, Node 18+, TypeScript 5.0+ | v9 dropped CJS support; project uses ESM via `next.config.mjs` — compatible. Webpack still required for SW compilation even with Turbopack in dev. |
| `serwist@^9.5.6` | `@serwist/next@9.x` | Must match major version. |
| `idb@^8.0.3` | Node 18+, all modern browsers | Pure client-side library; not used in server components. |
| `sharp@^0.34.5` | Node 18+, Next.js 16 | Native binaries via node-pre-gyp. `node:18-alpine` Docker image works. Already recommended by Next.js for image optimization. |
| `lru-cache@^11.x` | Node 18+, ESM and CJS | Hybrid module — supports both `import` and `require`. |
| `sonner@^2.0.7` | React 19, Next.js 16 | Zero deps. Client component only (needs `"use client"`). |

---

## Sources

- Serwist docs (official): https://serwist.pages.dev/docs/next — getting started, Turbopack support confirmed
- Serwist v9 blog post: https://serwist.pages.dev/blog/2024/03/10/serwist-v9 — ESM-only, Node 18+, Webpack now optional peer dep
- Next.js PWA guide (official): https://nextjs.org/docs/app/guides/progressive-web-apps — Serwist listed as recommended approach
- `idb` npm: https://github.com/jakearchibald/idb — v8.0.3, maintained by Jake Archibald (Chrome team)
- `file-type` v21 release: https://github.com/sindresorhus/file-type/releases — confirms Node.js 20+ requirement (HIGH confidence; disqualifies for Node 18 Docker)
- `sharp` npm: https://sharp.pixelplumbing.com/ — v0.34.5, recommended by Next.js for image optimization
- Next.js cookies() API: https://nextjs.org/docs/app/api-reference/functions/cookies — async in Next.js 15+, reads theme cookie in layout
- FreeCodeCamp in-memory rate limiter: https://www.freecodecamp.org/news/how-to-build-an-in-memory-rate-limiter-in-nextjs/ — January 2026 article confirming lru-cache pattern (MEDIUM confidence — WebSearch verified)
- `sonner` npm: https://www.npmjs.com/package/sonner — v2.0.7, zero deps, shadcn/ui official toast
- `lru-cache` npm: https://isaacs.github.io/node-lru-cache/ — official docs, hybrid module, TTL support
- Next.js self-hosting guide: https://nextjs.org/docs/app/guides/self-hosting — recommends nginx reverse proxy for rate limiting at infrastructure layer (alternative to in-process)

---

*Stack research for: StoreCard — production hardening (offline PWA, security, performance, error handling)*
*Researched: 2026-02-28*
