# Feature: User Profile Page

**Version:** 1.0.0
**Target Release:** v1.0.2

## Overview

Add an authenticated profile page (`/profile`) where logged-in users can view their account info and change their password. The feature adds no new dependencies, no schema changes, and preserves all 8 closed vulnerabilities.

## What It Does

1. **`GET /profile`** — session-gated page showing the user's username and email (read-only, HTML-escaped), plus a change-password form with CSRF protection
2. **`POST /profile/password`** — validates current password via bcrypt, hashes new password via bcrypt, runs parameterized UPDATE
3. **Dashboard link** — adds a "Profile" nav link next to Logout on the dashboard

## Key Design Decisions

- No schema change (uses existing `id, username, email, password` columns only)
- No new middleware (CSRF, rate-limit, session all apply automatically)
- No new dependencies (stdlib only)
- Template uses same `str.replace` pattern as other pages (no template engine)
- Password strength policy enforced server-side (≥8 chars, upper, lower, digit, special)
- Theme toggle stays frontend-only (localStorage)

## Files Touched

| File | Change |
|------|--------|
| `frontend/templates/profile.html` | New — profile page template |
| `backend/app/api/routes/auth.py` | Add GET /profile, POST /profile/password handlers |
| `backend/app/services/auth_service.py` | Add change_password() function |
| `frontend/templates/dashboard.html` | Add Profile link to hero-right |
| `frontend/static/css/styles.css` | Append profile page CSS rules |
| `README.md` | Update feature table + API endpoints |
| `CLAUDE.md` | Update integration docs + rules + spec hierarchy |
