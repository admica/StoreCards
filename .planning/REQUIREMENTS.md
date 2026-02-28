# Requirements: StoreCard

**Defined:** 2026-02-28
**Core Value:** Users can reliably store and retrieve their loyalty cards — including barcodes that scan at the register — even when offline.

## v1 Requirements

Requirements for production launch. Each maps to roadmap phases.

### Bug Fixes

- [x] **BUG-01**: "Skip for now" on subscribe page sets `subscriptionSelected = true` and redirects to dashboard (currently infinite redirect loop)
- [x] **BUG-02**: Uploaded images deleted from disk when card is deleted (`fs.unlink` the file in `public/uploads/`)
- [x] **BUG-03**: Old image file cleaned up when card image is replaced via update
- [ ] **BUG-04**: Barcode component shows error state instead of blank when bwip-js render fails (fallback: raw number + copy button)
- [ ] **BUG-05**: JWT callback only refreshes subscription data on `trigger === 'update'`, not on every request

### Security

- [x] **SEC-01**: File uploads validated server-side via magic bytes + sharp re-encode (not `file.type` header)
- [x] **SEC-02**: Rate limiting on login/register endpoints (5 attempts per IP per 15 minutes, in-memory via lru-cache)
- [x] **SEC-03**: Barcode format validated against allowed enum values before storing in DB

### Code Quality

- [x] **QUAL-01**: Barcode scanning logic extracted into shared `useBarcodeScanner` hook (deduplicate add/edit forms)
- [x] **QUAL-02**: Brand logo caching extracted into `cacheBrandLogo` helper (deduplicate createCard/updateCard)
- [x] **QUAL-03**: Dead code removed: `onboardingComplete` field (schema migration + auth config), empty email verification directories, `extractColorsFromUrl` stub
- [x] **QUAL-04**: `useFormState` migrated to `useActionState` across all forms (React 19 migration)
- [x] **QUAL-05**: `dangerouslySetInnerHTML` SW script replaced with `next/script` component

### Performance

- [ ] **PERF-01**: Theme preference stored in cookie; root layout reads via `cookies()` with no DB query
- [ ] **PERF-02**: Theme toggle writes cookie via Server Action; DB `darkMode` field kept as fallback for first login only
- [x] **PERF-03**: Logo search runs Clearbit + logo.dev in parallel via `Promise.all` (currently sequential)

### UX Polish

- [ ] **UX-01**: Categorized barcode scan error messages with actionable remediation text (permission denied, camera not found, decode failure)
- [ ] **UX-02**: Inline client-side form validation on register, login, and card forms (validate on blur, field-level errors)
- [ ] **UX-03**: Empty state for dashboard with no cards (illustration + "Add your first card" CTA)
- [ ] **UX-04**: Loading/pending states on all Server Action buttons (spinner or "Saving...")
- [ ] **UX-05**: Toast notification system for non-blocking errors (image upload failures, network errors) via sonner

### Subscription & Billing

- [ ] **SUB-01**: Subscription status card in settings (current tier, renewal date, status)
- [ ] **SUB-02**: Cancel subscription button with confirmation modal ("active until [date]" messaging)
- [ ] **SUB-03**: Stripe Customer Portal link in settings ("Manage billing, update payment method")
- [ ] **SUB-04**: Subscribe page UX improved — "Choose Free" is the prominent default path

### Account Management

- [ ] **ACCT-01**: User can delete their account from settings (two-step confirmation)
- [ ] **ACCT-02**: Account deletion cascade: cancel Stripe subscription → delete card files → delete all DB records → sign out

### PWA Offline

- [ ] **PWA-01**: Serwist service worker replaces hand-rolled `public/sw.js` with build-hash-versioned precache
- [ ] **PWA-02**: Dashboard and card pages cached (network-first with cache fallback) for offline access
- [ ] **PWA-03**: Card images cached (cache-first) for offline barcode display at store register
- [ ] **PWA-04**: Offline fallback page shown for uncached routes (branded, not browser error)
- [ ] **PWA-05**: Offline indicator banner when `navigator.onLine === false`
- [ ] **PWA-06**: PWA install prompt after first card added

### Feature Gating

- [ ] **GATE-01**: `lib/feature-gate.ts` with `requireFeature()` function using DB-authoritative subscription checks (not JWT)
- [ ] **GATE-02**: `TIER_FEATURES` configuration mapping subscription tiers to capability flags
- [ ] **GATE-03**: Gate enforcement in Server Actions (mutation prevention) and Server Components (UI rendering)
- [ ] **GATE-04**: "Upgrade required" error handling in UI when gated feature accessed

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Cards

- **CARD-01**: Card sort by last used / alphabetical
- **CARD-02**: Card search by retailer name
- **CARD-03**: Dashboard pagination for 50+ cards

### Offline

- **OFF-01**: Offline card creation queue (IndexedDB + Background Sync + conflict resolution)

### Billing

- **BILL-01**: Define specific feature gates per subscription tier (card count limit, export, etc.)

## Out of Scope

| Feature | Reason |
|---------|--------|
| OAuth / social login | Increases dependency surface; email/password sufficient for v1 |
| Card sharing between users | Requires permissions model, shared ownership semantics — different product |
| Real-time points balance sync | No standardized retailer APIs; notes field covers this |
| Push notifications | Requires retailer data feeds; unrelated to card storage value |
| Admin dashboard | Single-tenant self-hosted; Stripe Dashboard + Prisma Studio sufficient |
| i18n / multi-language | No clear demand; doubles copy maintenance |
| Email verification | Abandoned feature (dead directories exist); adds friction for controlled user base |
| Mobile native app | PWA covers mobile use case — this IS the differentiator |
| Drag-and-drop card reorder | Sort-by-last-used achieves the goal automatically |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| BUG-01 | Phase 1 | Complete |
| BUG-02 | Phase 1 | Complete |
| BUG-03 | Phase 1 | Complete |
| BUG-04 | Phase 2 | Pending |
| BUG-05 | Phase 3 | Pending |
| SEC-01 | Phase 1 | Complete |
| SEC-02 | Phase 1 | Complete |
| SEC-03 | Phase 1 | Complete |
| QUAL-01 | Phase 1 | Complete |
| QUAL-02 | Phase 1 | Complete |
| QUAL-03 | Phase 1 | Complete |
| QUAL-04 | Phase 1 | Complete |
| QUAL-05 | Phase 1 | Complete |
| PERF-01 | Phase 3 | Pending |
| PERF-02 | Phase 3 | Pending |
| PERF-03 | Phase 1 | Complete |
| UX-01 | Phase 2 | Pending |
| UX-02 | Phase 2 | Pending |
| UX-03 | Phase 2 | Pending |
| UX-04 | Phase 2 | Pending |
| UX-05 | Phase 2 | Pending |
| SUB-01 | Phase 4 | Pending |
| SUB-02 | Phase 4 | Pending |
| SUB-03 | Phase 4 | Pending |
| SUB-04 | Phase 4 | Pending |
| ACCT-01 | Phase 4 | Pending |
| ACCT-02 | Phase 4 | Pending |
| PWA-01 | Phase 5 | Pending |
| PWA-02 | Phase 5 | Pending |
| PWA-03 | Phase 5 | Pending |
| PWA-04 | Phase 5 | Pending |
| PWA-05 | Phase 5 | Pending |
| PWA-06 | Phase 5 | Pending |
| GATE-01 | Phase 6 | Pending |
| GATE-02 | Phase 6 | Pending |
| GATE-03 | Phase 6 | Pending |
| GATE-04 | Phase 6 | Pending |

**Coverage:**
- v1 requirements: 37 total
- Mapped to phases: 37
- Unmapped: 0 ✓

---
*Requirements defined: 2026-02-28*
*Last updated: 2026-02-28 after roadmap creation — all 37 requirements mapped to ROADMAP.md phases*
