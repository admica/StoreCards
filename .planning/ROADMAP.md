# Roadmap: StoreCard

## Overview

StoreCard is a functional loyalty card PWA that needs production hardening before public launch. The existing application works end-to-end but has real bugs, security gaps, performance issues, and incomplete features. This roadmap works through those gaps systematically: fix what's broken first, then polish the user experience, then complete the billing surface, then deliver the core offline value proposition, and finally activate the freemium business model with feature gating.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Bug Fixes and Security** - Close live bugs and security gaps before any public user signs up (completed 2026-02-28)
- [x] **Phase 2: UX Quality and Error Handling** - Barcode errors, form validation, empty states, and loading feedback (completed 2026-02-28)
- [ ] **Phase 3: Performance Cleanup** - Cookie-based theme and JWT refresh fix eliminate DB queries on every render
- [ ] **Phase 4: Subscription and Account Management** - Complete billing UI and GDPR account deletion
- [ ] **Phase 5: PWA Offline Support** - Cache cards and barcodes so the core use case works without network
- [ ] **Phase 6: Feature Gating Infrastructure** - Build the enforcement layer that activates the freemium model

## Phase Details

### Phase 1: Bug Fixes and Security
**Goal**: The application is safe for public users — auth works reliably, uploads are secure, and the subscription flow is navigable
**Depends on**: Nothing (first phase)
**Requirements**: BUG-01, BUG-02, BUG-03, SEC-01, SEC-02, SEC-03, QUAL-01, QUAL-02, QUAL-03, QUAL-04, QUAL-05, PERF-03
**Success Criteria** (what must be TRUE):
  1. User can click "Skip for now" on the subscribe page and reach the dashboard without any redirect loop
  2. Deleting a card removes its image file from disk (no orphaned files accumulate in public/uploads/)
  3. Replacing a card image removes the old file from disk
  4. An attacker who uploads a file with a fake image Content-Type header cannot store non-image content in public/uploads/
  5. Logging in with wrong credentials 6+ times within 15 minutes returns an error rather than allowing unlimited attempts
**Plans:** 3/3 plans complete

Plans:
- [x] 01-01-PLAN.md — Fix subscribe redirect loop, image security/cleanup, barcode validation, parallel logos
- [x] 01-02-PLAN.md — Rate limiting via proxy.ts, dead code removal, SW script replacement
- [ ] 01-03-PLAN.md — Extract barcode scanner hook, deduplicate logo caching, migrate useFormState to useActionState

### Phase 2: UX Quality and Error Handling
**Goal**: Users get actionable feedback when things go wrong and a polished experience throughout the core card workflow
**Depends on**: Phase 1
**Requirements**: BUG-04, UX-01, UX-02, UX-03, UX-04, UX-05
**Success Criteria** (what must be TRUE):
  1. When barcode scanning fails, the user sees a specific message (permission denied, camera not found, or decode failure) with instructions for what to do next
  2. When bwip-js fails to render a barcode, the raw barcode number is shown with a copy button instead of a blank error
  3. A user with no cards sees an illustration and "Add your first card" call-to-action instead of an empty screen
  4. Every form (register, login, add card, edit card) shows field-level errors immediately after leaving an invalid field
  5. Buttons that trigger Server Actions show a spinner or "Saving..." while the action is in flight
**Plans:** 3/3 plans complete

Plans:
- [ ] 02-01-PLAN.md — Foundation: sonner install, shared SubmitButton, validation schemas, Barcode error fallback, empty state
- [ ] 02-02-PLAN.md — Categorized scan errors in useBarcodeScanner + card form validation and error UI
- [ ] 02-03-PLAN.md — Auth form blur validation + SubmitButton wiring into login, register, subscribe

### Phase 3: Performance Cleanup
**Goal**: Root layout renders with zero database queries; JWT session refresh is scoped to deliberate user updates only
**Depends on**: Phase 1
**Requirements**: BUG-05, PERF-01, PERF-02
**Success Criteria** (what must be TRUE):
  1. Switching between dark and light mode persists immediately and survives a page reload with no flash of wrong theme
  2. A fresh page load does not trigger any database query for theme preference (cookie is the source of truth)
  3. A user whose Stripe subscription was cancelled sees the correct cancelled status on their next page load without requiring a sign-out and sign-in
**Plans**: TBD

### Phase 4: Subscription and Account Management
**Goal**: Users can understand their billing status, manage their subscription, and permanently delete their account
**Depends on**: Phase 3
**Requirements**: SUB-01, SUB-02, SUB-03, SUB-04, ACCT-01, ACCT-02
**Success Criteria** (what must be TRUE):
  1. Settings page shows the user's current tier (Free or paid), subscription status, and renewal date
  2. User can cancel their subscription from settings with a confirmation step that shows the date access ends
  3. User can open the Stripe Customer Portal from settings to update their payment method or view invoices
  4. Subscribe page makes "Continue with Free" the visually prominent default path with paid plans as secondary options
  5. User can delete their account from settings, which cancels any Stripe subscription, removes all card images, deletes all database records, and signs them out
**Plans**: TBD

### Phase 5: PWA Offline Support
**Goal**: Users can pull up any of their stored cards — including the scannable barcode — at the store register even without a network connection
**Depends on**: Phase 4
**Requirements**: PWA-01, PWA-02, PWA-03, PWA-04, PWA-05, PWA-06
**Success Criteria** (what must be TRUE):
  1. With the network disabled after a previous visit, the user can open the dashboard and see their cards
  2. With the network disabled, the user can open any card's detail page and see the full barcode ready to scan
  3. Navigating to an uncached route while offline shows a branded offline page rather than the browser's default error screen
  4. A banner appears at the top of the page when the device has no network connection
  5. After adding their first card, the user sees a prompt to install StoreCard as an app on their device
**Plans**: TBD

### Phase 6: Feature Gating Infrastructure
**Goal**: The freemium model has a working enforcement layer — gated features are blocked server-side based on subscription tier, not just hidden in the UI
**Depends on**: Phase 4
**Requirements**: GATE-01, GATE-02, GATE-03, GATE-04
**Success Criteria** (what must be TRUE):
  1. A user who calls a gated Server Action directly via fetch() receives an "Upgrade required" error, not data
  2. Gated UI elements render differently (locked state or upgrade prompt) for Free-tier users viewing the relevant page
  3. Changing a user's subscription tier in the database is immediately reflected in gate checks on their next request without any cache invalidation step
  4. The TIER_FEATURES configuration is a single file that lists which capabilities belong to which subscription tier
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Bug Fixes and Security | 3/3 | Complete   | 2026-02-28 |
| 2. UX Quality and Error Handling | 3/3 | Complete   | 2026-02-28 |
| 3. Performance Cleanup | 0/TBD | Not started | - |
| 4. Subscription and Account Management | 0/TBD | Not started | - |
| 5. PWA Offline Support | 0/TBD | Not started | - |
| 6. Feature Gating Infrastructure | 0/TBD | Not started | - |
