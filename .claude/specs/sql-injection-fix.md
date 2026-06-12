# Software Specification Document — SQL Injection Fix

**Version:** 1.0.0
**Last Updated:** June 12, 2026
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md), [bcrypt-password-hashing.md](./bcrypt-password-hashing.md)

---

## 1. Overview / Purpose

This document specifies the remediation of **Vulnerability #1 — SQL Injection** in the Vulnerable Web Application. The current implementation in `backend/app/services/auth_service.py` constructs SQL queries using **string concatenation** of untrusted user input (`username`, `email`, `password`), allowing attackers to inject arbitrary SQL via specially crafted payloads. This fix replaces all string concatenation with **parameterized queries** (prepared statements) using sqlite3's `?` placeholder syntax, which separates SQL logic from data and guarantees that user input is treated as literal values rather than executable SQL. The fix closes **vulnerability #1 only**; the six other intentional vulnerabilities remain in place for educational use.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- Replace string concatenation in `auth_service.signup()` with parameterized queries.
- Replace string concatenation in `auth_service.login()` with parameterized queries.
- Preserve all existing function signatures, return types, and error behaviors.
- Maintain compatibility with the bcrypt-based password hashing (VULN-5 already closed).
- Ensure the fix works with the existing SQLite schema and connection layer.

### 2.2 Out of Scope (Intentionally Unfixed)

This fix is **surgical** and addresses only Vulnerability #1. The following intentional vulnerabilities remain in place after this fix and MUST NOT be remediated in the same change:

| # | Vulnerability | Status under this fix |
|---|---------------|-----------------------|
| **1** | **SQL Injection (string-concatenated queries)** | **CLOSED by this spec** |
| 2 | Stored XSS (`{{username}}` substitution in dashboard) | Intentionally unchanged |
| 3 | Reflected XSS (`/search?q=` reflection) | Intentionally unchanged |
| 4 | Session Hijacking (hardcoded `"super-secret-key-12345"`) | Intentionally unchanged |
| 5 | Weak Password Storage | Already closed (bcrypt) — preserved |
| 6 | Exposed Database (`/download/db` open endpoint) | Intentionally unchanged |
| 7 | No Rate Limiting | Intentionally unchanged |
| 8 | CSRF (no tokens) | Intentionally unchanged |

### 2.3 Explicit Preservation Note

All other intentional vulnerabilities MUST remain unchanged:
- VULN-2: No escaping of `{{username}}` in dashboard
- VULN-3: No escaping of `q` query parameter in `/search`
- VULN-4: Session secret remains `"super-secret-key-12345"`
- VULN-6: `/download/db` remains unauthenticated
- VULN-7: No rate limiting middleware added
- VULN-8: No CSRF tokens added to forms

---

## 3. Affected Files

The fix MUST touch only the following file. No other repository file may be created or modified.

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/services/auth_service.py` | Modified | Replace string concatenation with parameterized queries in `signup()` and `login()` |

Files that MUST NOT be modified by this change:

- `backend/app/core/security.py` (bcrypt implementation — VULN-5 already closed, must remain)
- `backend/app/main.py` (session middleware secret — preserves VULN-4).
- `backend/app/api/routes/auth.py` (routes, dashboard substitution, `/download/db`, `/search` — preserves VULN-2, VULN-3, VULN-6).
- `backend/app/db/session.py` (schema and connection layer — no changes needed).
- `backend/pyproject.toml`, `pyproject.toml` (no new dependencies).
- Any HTML template under `frontend/templates/` or CSS under `frontend/static/`.
- `CLAUDE.md`, `docs/PRD.md`, `docs/TDD.md`.

---

## 4. Functional Requirements

### FR-01: Parameterized Query in signup()

- `auth_service.signup()` MUST construct the `INSERT` query using parameterized syntax:
  - Query template: `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`
  - Values passed via `conn.execute(query, [username, email, hashed])` (or equivalent tuple/list)
- No string concatenation MAY appear in the query construction.
- The function's return values, error handling, and control flow MUST remain identical to the current implementation.

### FR-02: Parameterized Query in login()

- `auth_service.login()` MUST construct the `SELECT` query using parameterized syntax:
  - Query template: `SELECT * FROM users WHERE username = ?`
  - Values passed via `conn.execute(query, [username])` (or equivalent)
- No string concatenation MAY appear in the query construction.
- The function's return values, error handling, and control flow MUST remain identical to the current implementation.

### FR-03: Error Behavior Preservation

- `signup()` MUST continue to return `HTMLResponse` with HTTP 400 for:
  - Missing fields
  - `sqlite3.IntegrityError` (username already exists)
  - Any other exception
- `login()` MUST continue to return `JSONResponse` with HTTP 401 for:
  - Missing fields
  - Database errors
  - Invalid credentials (no user found or password mismatch)

### FR-04: Session Behavior

- `login()` MUST continue to set the same three session keys on successful authentication:
  - `request.session["user_id"] = user["id"]`
  - `request.session["username"] = user["username"]`
  - `request.session["email"] = user["email"]`
- The redirect URL `/welcome` and success JSON structure MUST remain unchanged.

### FR-05: Password Verification

- `login()` MUST continue to call `verify_password(password, user["password"])` for password comparison.
- The bcrypt-based verification (VULN-5 closed) MUST remain untouched.

---

## 5. Non-Functional Requirements

### NFR-01: SQL Injection Immunity

- All user input MUST be treated as literal values by the database engine.
- No SQL keywords or operators injected via user input can alter the query structure.
- A payload like `admin' OR '1'='1' --` MUST result in a literal username lookup for that exact string (which will fail to match any real user).

### NFR-02: API Stability

- The public signatures of `signup()` and `login()` MUST remain byte-identical.
- All callers (route handlers in `auth.py`) continue to work without modification.

### NFR-03: Surgical Scope

- Exactly one vulnerability (VULN-1) is closed by this change.
- The diff MUST NOT touch session secrets, CSRF posture, XSS escape logic, rate limiting, or the `/download/db` route.

### NFR-04: Backward Compatibility

- Existing user accounts in `vulnerable_app.db` continue to work without migration.
- The bcrypt password hashes already in the database continue to verify correctly.

### NFR-05: Performance

- Parameterized queries incur no measurable performance penalty; the fix is a drop-in replacement for string concatenation.

### NFR-06: Error Information Leakage

- The error messages and HTTP status codes MUST remain exactly the same as before.
- No new information is leaked about the internal query structure or validation failures.

---

## 6. Success Paths

### SP-01: Successful Signup

1. User submits signup form with `username=alice`, `email=alice@test.com`, `password=pass123`.
2. `auth_service.signup()` executes parameterized `INSERT` query.
3. Row is inserted into `users` table.
4. Server returns `RedirectResponse` to `/login` (HTTP 302).

### SP-02: Successful Login

1. User submits login form with `username=alice`, `password=pass123`.
2. `auth_service.login()` executes parameterized `SELECT WHERE username = ?` query.
3. Row is fetched and `verify_password()` returns `True`.
4. Session is populated with user data.
5. Server returns JSON `{"success": true, "redirect": "/welcome"}` (HTTP 200).

### SP-03: Login with SQL Injection Payload

1. Attacker submits login with `username=admin' OR '1'='1' --`, `password=anything`.
2. The parameterized query treats the entire payload as a literal username string.
3. No user with that literal username exists in the database.
4. Server returns JSON 401 with `{"error": "Invalid username or password"}`.
5. **No authentication bypass occurs.**

### SP-04: Signup with SQL Injection Payload

1. Attacker submits signup with `username=test', 'test@test.com', 'hash') --`, etc.
2. The parameterized query treats the entire payload as a literal username.
3. Either the `INSERT` succeeds with that literal username (malformed but harmless) or fails validation.
4. **No SQL injection occurs; no data exfiltration or corruption.**

---

## 7. Edge Cases

### EC-01: Single Quote in Username

- A user registers with username `o'neill` (contains a literal apostrophe).
- The parameterized query handles the quote correctly without escaping.
- Signup succeeds and login with `username=o'neill` succeeds.

### EC-02: SQL Keywords in Input

- A user attempts to register with username `admin; DROP TABLE users; --`.
- The parameterized query treats it as a literal string.
- Either signup succeeds with that literal username (allowed by schema) or fails validation.
- **No table is dropped.**

### EC-03: NULL Character in Input

- Input containing a null byte (`\x00`) is passed to the query.
- SQLite's parameterized binding handles null bytes as literal characters.
- No injection or buffer overflow occurs.

### EC-04: Empty String Parameters

- `username=""` with valid password results in the parameterized query looking for an empty string.
- No user matches, resulting in HTTP 401.
- Behavior is identical to pre-fix implementation.

### EC-05: Very Long Input

- Input exceeding typical field lengths (e.g., 10,000-character username) is passed to the parameterized query.
- SQLite's `TEXT` column type accommodates the input.
- No injection vector exists regardless of length.

### EC-06: Unicode Input

- User registers with `username=日本語`, `email=test@example.com`, `password=パスワード`.
- Parameterized query handles UTF-8 encoding correctly.
- Signup and login both succeed.

---

## 8. Acceptance Criteria

### AC-01: signup() Uses Parameterized Query

- The `signup()` function contains a query string with `?` placeholders.
- The query is executed with a list/tuple of values, not via concatenation.

### AC-02: login() Uses Parameterized Query

- The `login()` function contains a query string with `?` placeholders.
- The query is executed with a list/tuple of values, not via concatenation.

### AC-03: No String Concatenation in Queries

- `grep` for query construction shows no `+` or `f"` string concatenation with user input.

### AC-04: SQL Injection Payload Fails

- Attempting to log in with `username=admin' OR '1'='1' --` returns HTTP 401.
- No user is authenticated.

### AC-05: Normal Signup Still Works

- A new user can successfully register via `/signup`.
- The user can then log in and access `/welcome`.

### AC-06: Normal Login Still Works

- Existing user accounts can log in successfully.
- Session data is set correctly.

### AC-07: Error Messages Preserved

- All error responses have identical text and HTTP status codes as before.
- No new information is leaked.

### AC-08: Other Vulnerabilities Preserved

- VULN-2 (Stored XSS): Registering `<script>alert(1)</script>` still triggers script execution.
- VULN-3 (Reflected XSS): `/search?q=<script>alert(1)</script>` still reflects unescaped.
- VULN-4 (Session secret): `"super-secret-key-12345"` still present in `main.py`.
- VULN-6 (Exposed DB): `/download/db` still serves SQLite file unauthenticated.
- VULN-7 (No rate limit): No throttling middleware added.
- VULN-8 (No CSRF): No CSRF tokens added to forms.

### AC-09: Affected Files Limited

- Only `backend/app/services/auth_service.py` is modified.
- No other files appear in `git status`.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Normal signup succeeds | Empty DB | User created, redirect to `/login` |
| TC-02 | Normal login succeeds | User `alice` exists with known password | HTTP 200, success JSON, session set |
| TC-03 | SQLi payload in login fails | User `alice` exists | `username=alice' OR '1'='1' --` returns HTTP 401 |
| TC-04 | SQLi payload in signup fails | Empty DB | `username=test', 'x@x', 'hash') --` creates harmless user or fails validation; no injection |
| TC-05 | Single quote in username works | Empty DB | `username=o'neill` registers and logs in successfully |
| TC-06 | SQL keywords in input handled | Empty DB | `username=admin; DROP TABLE users; --` either creates user with literal name or fails; no table dropped |
| TC-07 | Empty username returns 401 | Any DB state | `username=""`, valid password returns HTTP 401 |
| TC-08 | Wrong password returns 401 | User exists | HTTP 401 with standard error JSON |
| TC-09 | Unknown username returns 401 | Any DB state | HTTP 401 with standard error JSON |
| TC-10 | Duplicate username returns 400 | User exists | HTTP 400 with "Username already exists" HTML |
| TC-11 | Unicode input works | Empty DB | `username=日本語`, UTF-8 password registers and logs in |
| TC-12 | Very long input handled | Empty DB | 10,000-char username either succeeds or fails validation; no injection |
| TC-13 | Stored XSS still fires (VULN-2 preserved) | App running | Register `<img src=x onerror=alert(1)>`, log in, visit `/welcome` → alert fires |
| TC-14 | Reflected XSS still fires (VULN-3 preserved) | App running | `/search?q=<script>alert(1)</script>` reflects payload |
| TC-15 | Session secret unchanged (VULN-4 preserved) | App running | `grep 'super-secret-key-12345' backend/app/main.py` matches |
| TC-16 | `/download/db` still open (VULN-6 preserved) | App running | Unauthenticated GET returns HTTP 200 with SQLite file |
| TC-17 | No CSRF tokens (VULN-8 preserved) | App running | HTML forms lack `csrf_token` input |
| TC-18 | No rate limiting (VULN-7 preserved) | App running | Repeated login requests not throttled |

---

## 10. Verification Steps

Run from the repository root.

### 10.1 Start the Application

```bash
uv run backend/app/main.py
```

The server listens on `http://localhost:3001`.

### 10.2 Functional Walkthrough

1. **Register a user** — `http://localhost:3001/signup`
   - Submit `username=alice`, `email=alice@test.com`, `password=pass123`.
   - Expect a redirect to `/login`.

2. **Verify user created**
   ```bash
   sqlite3 vulnerable_app.db "SELECT username FROM users WHERE username='alice';"
   ```
   Expected: returns `alice`.

3. **Successful login** (TC-02)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode 'username=alice' \
        --data-urlencode 'password=pass123'
   ```
   Expected: HTTP 200, body `{"success": true, "redirect": "/welcome"}`.

### 10.3 SQL Injection Payload Tests

1. **Classic OR injection in login** (TC-03)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode "username=admin' OR '1'='1' --" \
        --data-urlencode 'password=anything'
   ```
   Expected: HTTP 401, `{"error":"Invalid username or password"}`.

2. **Tautology injection** (TC-03)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode "username=' OR '1'='1' --" \
        --data-urlencode 'password=x'
   ```
   Expected: HTTP 401.

3. **Comment-based injection** (TC-03)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode "username=alice' --" \
        --data-urlencode 'password=wrongpass'
   ```
   Expected: HTTP 401 (the literal username `alice' --` does not match any user).

### 10.4 Edge Case Tests

1. **Single quote in username** (TC-05)
   ```bash
   # Register
   curl -s -i -X POST http://localhost:3001/signup \
        --data-urlencode "username=o'neill" \
        --data-urlencode 'email=oneill@test.com' \
        --data-urlencode 'password=pass123'
   # Login
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode "username=o'neill" \
        --data-urlencode 'password=pass123'
   ```
   Expected: Registration succeeds (302 to `/login`), login succeeds (200).

2. **SQL keywords in username** (TC-06)
   ```bash
   curl -s -i -X POST http://localhost:3001/signup \
        --data-urlencode "username=admin; DROP TABLE users; --" \
        --data-urlencode 'email=drop@x' \
        --data-urlencode 'password=x'
   ```
   Expected: Either successful signup with literal username or validation error; **no table dropped**.

3. **Empty username** (TC-07)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode 'username=' \
        --data-urlencode 'password=pass123'
   ```
   Expected: HTTP 401.

### 10.5 Vulnerability Preservation Walkthrough

```bash
# VULN-2: Stored XSS still fires (TC-13)
curl -s -i -X POST http://localhost:3001/signup \
     --data-urlencode 'username=<img src=x onerror=alert(1)>' \
     --data-urlencode 'email=xss@x' \
     --data-urlencode 'password=p'
# Then log in and visit /welcome in a browser — alert should fire.

# VULN-3: Reflected XSS (TC-14)
curl -s 'http://localhost:3001/search?q=<script>alert(1)</script>' | grep -o '<script>alert(1)</script>'
# Expected: payload found in response.

# VULN-4: Session secret unchanged (TC-15)
grep -n 'super-secret-key-12345' backend/app/main.py
# Expected: matches a line.

# VULN-6: /download/db still open (TC-16)
curl -s -o /tmp/dl.db -w 'status=%{http_code}\n' http://localhost:3001/download/db
file /tmp/dl.db
# Expected: status=200, file is SQLite database.

# VULN-8: No CSRF tokens (TC-17)
curl -s http://localhost:3001/login | grep -i csrf || echo 'No CSRF token (preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo 'No CSRF token (preserved)'
# Expected: no CSRF token fields.
```

### 10.6 Code Inspection

```bash
# Verify no string concatenation in queries
grep -n "VALUES.*'" backend/app/services/auth_service.py || echo 'No concatenation in signup'
grep -n "WHERE.*'" backend/app/services/auth_service.py || echo 'No concatenation in login'

# Verify parameterized query syntax
grep -n "VALUES (?, ?, ?)" backend/app/services/auth_service.py
grep -n "WHERE username = ?" backend/app/services/auth_service.py

# Verify execute() is called with parameters
grep -n "execute.*\[" backend/app/services/auth_service.py
```

### 10.7 Affected-Files Audit

```bash
git status --porcelain
```

Expected output — exactly one modified file:

```
 M backend/app/services/auth_service.py
```

---

## 11. Migration & Operational Note

This fix requires **no database migration or data changes**. Existing user accounts continue to work without modification because:

1. The SQLite schema is unchanged.
2. The bcrypt password hashes already in the database are unchanged.
3. The password verification logic (`verify_password()`) is unchanged.

The only change is how queries are constructed at runtime. After deploying this change:

- No user action is required.
- Existing users can log in with their existing credentials.
- New users can sign up and log in normally.
- SQL injection attacks are neutralized.