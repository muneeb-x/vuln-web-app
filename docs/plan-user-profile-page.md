# Implementation Plan — User Profile Page

**Target Release:** v1.0.2

## Phases

### Phase 1 — Service Layer: `change_password()` in `auth_service.py`

Add `import re` and a `password_meets_policy()` helper, then `change_password()`:
- Reads `user_id` from session (401 if absent)
- Validates non-empty fields (400 if empty)
- Enforces password policy (≥8, lower, upper, digit, special)
- Parameterized `SELECT * FROM users WHERE id = ?`
- Verifies current password with `verify_password()` (bcrypt)
- Hashes new password with `hash_password()` (bcrypt)
- Parameterized `UPDATE users SET password = ? WHERE id = ?`
- Returns JSON for every outcome

### Phase 2 — Route Handlers in `auth.py`

- `GET /profile` — session gate, load template, splice CSRF token + escaped username/email
- `POST /profile/password` — thin forwarder to `auth_service.change_password()`

### Phase 3 — Template: `frontend/templates/profile.html`

- Shared header with theme toggle + logos
- Hero banner with Dashboard + Logout links
- Account Information card (escaped username + email)
- Change Password form (CSRF hidden field first, current pw, new pw, confirm, inline message)
- Fetch-based submit with `URLSearchParams` (urlencoded for CSRF)

### Phase 4 — Dashboard Link

Add `<a href="/profile" class="btn btn-logout">Profile</a>` to hero-right block.

### Phase 5 — CSS

Append `.profile-content`, `.profile-card`, `.profile-field`, `.profile-message` rules using existing `var(--...)` theme properties.

### Phase 6 — Documentation

Update README.md (feature table, API endpoints) and CLAUDE.md (integration, rules, hierarchy).

### Phase 7 — End-to-End Verification

Test: unauthenticated redirect, profile render, wrong current pw, empty new pw, CSRF enforcement, successful change + re-login, XSS escaping, vulnerability preservation.
