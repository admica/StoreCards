---
status: complete
phase: 02-ux-quality-and-error-handling
source: [02-01-SUMMARY.md, 02-02-SUMMARY.md, 02-03-SUMMARY.md]
started: 2026-02-28T23:29:00Z
updated: 2026-02-28T23:55:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Login Form Blur Validation
expected: Go to /login. Type an invalid email (e.g., "abc") and tab to the password field. An error message should appear below the email field with a red border. Leave password empty and tab away — a password error should appear. Fix the email to a valid format and the error should clear automatically as you type.
result: pass

### 2. Register Form Blur Validation
expected: Go to /register. Type an invalid email and tab away — email error appears with red border. Type a short password (e.g., "ab") and tab away — "Password must be at least 6 characters" should appear. The hint text "Must be at least 6 characters" should be replaced by the error message (not duplicated). Correcting either field should clear its error as you type.
result: pass

### 3. Subscribe Page SubmitButton
expected: After registering a new account, you should land on /subscribe. The free plan button should say "Continue with Free" and show a spinner with "Saving..." text while processing.
result: pass

### 4. Barcode Error Fallback with Copy Button
expected: If a card's barcode fails to render (invalid format), instead of a broken/empty barcode the raw card number should be displayed with a "Copy" button. Clicking copy should show a brief "Copied" confirmation.
result: pass
note: Initially blocked by /add blank page. Passed on re-test after fix.

### 5. Dashboard Empty State CTA
expected: When logged in with no cards, the dashboard should show an "Add your first card" call-to-action (not "Add First Card").
result: pass

### 6. Toast Notifications (Theme-Aware)
expected: Toast notifications should appear at the top-center of the screen and respect your current theme (light or dark mode styling).
result: pass
note: Initially blocked by settings toggles bug. Passed on re-test after fix.

### 7. Retailer Field Blur Validation (Add Card)
expected: Go to /add (add card form). Leave the retailer/store name field empty and tab away — an error should appear. Type a valid name and the error should clear.
result: pass
note: Initially blocked by /add blank page. Passed on re-test after fix.

### 8. Camera Permission Denied Error
expected: On the add card form, if you deny camera permission when prompted, a clear error panel should replace the camera view explaining that camera access was denied (not a generic error or blank area).
result: pass

### 9. Scan Decode Failure with Retry
expected: On the add card form, if you upload an image that can't be decoded as a barcode, an error message should appear with a "Try again" button to retry without leaving the form.
result: pass

### 10. Shared SubmitButton in Card Forms
expected: The add card and edit card forms should show a styled submit button with a loading spinner and "Saving..." text while the form is being submitted.
result: pass

## Summary

total: 10
passed: 10
issues: 0
pending: 0
skipped: 0

## Gaps

### Fixed During UAT

- truth: "/add page renders the add card form"
  status: fixed
  reason: "User reported: i clicked 'Add First Card' and it went to a blank screen"
  severity: blocker
  test: 4
  root_cause: "Stale standalone build with missing SSR chunks; server running from deleted CWD"
  fix: "Rebuilt and restarted server"

- truth: "Settings toggles (Light Mode, Nerd Mode) work correctly"
  status: fixed
  reason: "User reported: toggle to Light Mode and toggle for Nerd Mode, are not working anymore on the settings page"
  severity: major
  test: 6
  root_cause: "setTheme in ThemeProvider not wrapped in useCallback; useEffect in DarkModeToggle had unstable dependency causing immediate revert"
  fix: "Wrapped setTheme/toggleTheme in useCallback, removed redundant useEffect in DarkModeToggle"
  artifacts:
    - app/providers/theme-provider.tsx
    - app/settings/dark-mode-toggle.tsx
