# Software Specification Document — Bcrypt Password Hashing

**Version:** 1.0.0
**Last Updated:** June 11, 2026
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)

---

## 1. Overview / Purpose

This document specifies the remediation of **Vulnerability #5 — Weak Password Storage** in the Vulnerable Web Application. The current implementation in `backend/app/core/security.py` hashes passwords with **unsalted MD5**, a cryptographically broken digest that is trivially reversible via rainbow tables. This fix replaces MD5 with **bcrypt** at a work factor of **≥ 12**, while preserving the public function signatures `hash_password(password)` and `verify_password(plain, hashed)` so existing call-sites elsewhere in the codebase keep working. Because bcrypt produces a per-call random salt, the existing login query — which embeds the password hash inside the `WHERE` clause — can no longer authenticate a user with a single equality match; `auth_service.login()` MUST therefore be modified to fetch the user record by `username` alone and compare the stored hash to the supplied password using `verify_password()` in Python. The fix closes **vulnerability #5 only**; the seven other intentional vulnerabilities remain in place for educational use.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- Replace the MD5 digest in `backend/app/core/security.py` with a bcrypt-based implementation (work factor ≥ 12).
- Preserve the public API: `hash_password(password: str) -> str` and `verify_password(plain: str, hashed: str) -> bool`.
- Make `verify_password()` defensively wrap `bcrypt.checkpw` in a `try/except` so any non-bcrypt value already in the database (e.g. legacy MD5 rows) returns `False` rather than crashing the process.
- Modify `auth_service.login()` so it fetches the user by `username` only and uses `verify_password()` for password comparison in Python.
- Add `bcrypt` as a runtime dependency in **both** `backend/pyproject.toml` and the **root** `pyproject.toml`.
- Document a database-reset / re-register migration note for any pre-existing user accounts whose stored password is an MD5 hex digest.

### 2.2 Out of Scope (Intentionally Unfixed)

This fix is **surgical** and addresses only Vulnerability #5. The following intentional vulnerabilities remain in place after this fix and MUST NOT be remediated in the same change:

| # | Vulnerability | Status under this fix |
|---|---------------|-----------------------|
| 1 | SQL Injection (`auth_service.py` string-concatenated queries) | Intentionally unchanged — see §2.3 |
| 2 | Stored XSS (`{{username}}` substitution in dashboard) | Intentionally unchanged |
| 3 | Reflected XSS (`/search?q=` reflection) | Intentionally unchanged |
| 4 | Session Hijacking (hardcoded `"super-secret-key-12345"`) | Intentionally unchanged |
| **5** | **Weak Password Storage (MD5 no-salt)** | **CLOSED by this spec** |
| 6 | Exposed Database (`/download/db` open endpoint) | Intentionally unchanged |
| 7 | No Rate Limiting | Intentionally unchanged |
| 8 | CSRF (no tokens) | Intentionally unchanged |

### 2.3 Explicit SQL-Injection Preservation Note

The login query in `auth_service.login()` MUST still use **string concatenation** for the username branch of the `WHERE` clause. Removing the password equality from the `WHERE` clause does NOT close VULN-1 — the username remains concatenated into the SQL string and continues to be injectable. Tests in §9 (TC-09) explicitly verify that a classic `' OR '1'='1' --` payload in the username field still alters the query. Switching to parameterized queries is the separate, future "SQLi fix" task and is out of scope here.

---

## 3. Affected Files

The fix MUST touch only the following four files. No other repository file may be created or modified.

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/core/security.py` | Modified | Replace MD5 with bcrypt; harden `verify_password()` against non-bcrypt inputs |
| `backend/app/services/auth_service.py` | Modified | Rewrite `login()` to fetch-by-username and compare via `verify_password()`; `signup()` body is unchanged in logic but its `hashed` value is now a bcrypt string |
| `backend/pyproject.toml` | Modified | Add `bcrypt` to `[project].dependencies` |
| `pyproject.toml` (repository root) | Modified | Add `bcrypt` to `[project].dependencies` |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` (session middleware secret — preserves VULN-4).
- `backend/app/api/routes/auth.py` (routes, dashboard substitution, `/download/db`, `/search` — preserves VULN-2, VULN-3, VULN-6).
- `backend/app/db/session.py` (schema and connection layer — `users.password TEXT` already wide enough for bcrypt strings).
- Any HTML template under `frontend/templates/` or CSS under `frontend/static/`.
- `CLAUDE.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`.

---

## 4. Functional Requirements

### FR-01: Hash Function Replacement

- `hash_password(password: str) -> str` MUST:
  - Encode the input password to bytes using UTF-8.
  - Generate a fresh random salt via `bcrypt.gensalt(rounds=N)` where **N ≥ 12**.
  - Return the resulting bcrypt hash as a UTF-8 `str` (decoded from the bytes returned by `bcrypt.hashpw`).
- The returned string MUST begin with the bcrypt identifier prefix `$2b$` (or `$2a$` / `$2y$` — the modern `bcrypt` PyPI package emits `$2b$`).
- Two calls to `hash_password()` with the **same** plaintext MUST return **different** strings (because bcrypt generates a per-call salt).

### FR-02: Verification Function

- `verify_password(plain: str, hashed: str) -> bool` MUST:
  - Encode both arguments to UTF-8 bytes.
  - Call `bcrypt.checkpw(plain_bytes, hashed_bytes)` inside a `try/except` block.
  - Return `True` only when `checkpw` returns `True`.
  - Return `False` for **any** exception raised by `checkpw` (notably `ValueError` raised when `hashed` is not a valid bcrypt string — e.g., a 32-character MD5 hex digest left over in the database).
- The function MUST NOT raise, log, or otherwise leak information about why a particular hashed value failed validation.

### FR-03: Work Factor

- The bcrypt work factor (cost / `rounds` parameter) MUST be **≥ 12** (the OWASP-recommended floor in 2026).
- The chosen factor MUST be expressed as a named module-level constant inside `security.py` (suggested: `BCRYPT_ROUNDS = 12`) so it is auditable in code review.

### FR-04: Login Flow Rewrite

- `auth_service.login()` MUST:
  1. Validate that `username` and `password` are non-empty (existing behavior preserved).
  2. Build a `SELECT * FROM users WHERE username = '<username>'` query that fetches the candidate row by username **only**. (String concatenation is preserved — see §2.3.)
  3. Execute the query and `fetchone()`.
  4. If no row is returned, respond with the existing JSON 401 `{"error": "Invalid username or password"}`.
  5. If a row is returned, call `verify_password(password, row["password"])`.
  6. On `True`, set `session["user_id"]`, `session["username"]`, `session["email"]` exactly as today and return `{"success": True, "redirect": "/welcome"}`.
  7. On `False`, return the same JSON 401 with the same error text.
- The handler MUST NOT vary its response timing, error text, or HTTP status between "no such user" and "wrong password" cases beyond what the original implementation already did.

### FR-05: Signup Flow

- `auth_service.signup()` MUST keep its current control flow. Its only behavioral change is that `hash_password()` now returns a bcrypt string (FR-01) instead of an MD5 hex digest. The SQL `INSERT` is unchanged.
- The `users.password` column already has type `TEXT` (see TDD.md §11.3); bcrypt hashes (60 chars) fit without schema change.

### FR-06: Dependency Declaration

- `backend/pyproject.toml` `[project].dependencies` MUST include `bcrypt>=4.0.0`.
- The root `pyproject.toml` `[project].dependencies` MUST include `bcrypt>=4.0.0`.
- The lock files (`uv.lock`, `requirements.txt`) MAY be regenerated as a side effect of `uv sync`, but they are not authored by hand and are not listed in §3 as "affected" because they are derived artifacts.

### FR-07: Migration Note

- After this change ships, **any existing user account whose stored password is a 32-character MD5 hex digest cannot log in**: `verify_password()` will return `False` because the legacy value is not a valid bcrypt string (FR-02). There is intentionally NO automatic on-login rehash.
- Operators MUST either:
  - Delete `vulnerable_app.db` and let `init_db()` recreate an empty schema on next start (preferred for the educational lab); **or**
  - Inform affected users to re-register via `/signup` so a fresh bcrypt hash is written.
- This note MUST be reflected in the verification commands in §10.

---

## 5. Non-Functional Requirements

### NFR-01: Cryptographic Strength

- Bcrypt at work factor 12 yields ≈ 250 ms per hash on a 2026-era developer laptop — a four-order-of-magnitude slowdown vs. MD5 — which is the intended brute-force mitigation.

### NFR-02: API Stability

- The two public function names and their signatures (`hash_password(password: str) -> str`, `verify_password(plain: str, hashed: str) -> bool`) MUST remain byte-identical so that any future caller importing them from `app.core.security` keeps compiling.

### NFR-03: Surgical Scope

- Exactly one vulnerability (VULN-5) is closed by this change. The diff MUST NOT touch session secrets, CSRF posture, XSS escape logic, rate limiting, the `/download/db` route, or the SQL-injection construction in `auth_service.py`'s `WHERE username = '<...>'` substring.

### NFR-04: No Information Leakage

- `verify_password()` MUST NOT distinguish in its return value, exception, or log output between "wrong password", "hash is malformed", or "hash is a legacy MD5". All non-true outcomes collapse to `False`.

### NFR-05: Deterministic Test Surface

- For test reproducibility, the bcrypt work factor SHOULD be expressed as a single named constant (`BCRYPT_ROUNDS`) so tests can monkey-patch it down for speed when desired. No test in this spec requires that override, but the named constant keeps the door open.

### NFR-06: Encoding Robustness

- Both `hash_password()` and `verify_password()` MUST encode inputs as UTF-8. A password containing non-ASCII characters (e.g. `pässwörd`) MUST be hashable and verifiable.

### NFR-07: Bcrypt 72-Byte Truncation Acknowledgement

- Bcrypt silently truncates the input password at 72 bytes. This behavior is inherent to the algorithm and is acceptable for this educational lab; no pre-hashing (e.g., SHA-256 stretch) is required by this spec.

---

## 6. Success Paths

### SP-01: New Account Signup

1. User submits the signup form with `username=alice`, `email=alice@test.com`, `password=pass123`.
2. `auth_service.signup()` calls `hash_password("pass123")` → a `$2b$12$...`-prefixed 60-character string.
3. The string is INSERTed into `users.password` (concatenated SQL — unchanged).
4. Server returns `RedirectResponse` to `/login`.
5. The stored database row's `password` column begins with `$2b$`.

### SP-02: Successful Login

1. User submits the login form with `username=alice`, `password=pass123`.
2. `auth_service.login()` builds `SELECT * FROM users WHERE username = 'alice'` and executes it.
3. The row is found.
4. `verify_password("pass123", row["password"])` returns `True`.
5. Session is populated and JSON `{"success": true, "redirect": "/welcome"}` is returned.

### SP-03: Failed Login — Wrong Password

1. User submits `username=alice`, `password=WRONG`.
2. The row for `alice` is fetched.
3. `verify_password("WRONG", row["password"])` returns `False`.
4. Server returns JSON 401 with `{"error": "Invalid username or password"}`.

### SP-04: Failed Login — Unknown Username

1. User submits `username=nobody`, `password=anything`.
2. The `SELECT` returns zero rows.
3. Server returns JSON 401 with `{"error": "Invalid username or password"}`.
4. `verify_password()` is **not** called (no row to compare against).

### SP-05: Two Users, Same Password, Distinct Hashes

1. User `alice` registers with password `secret`.
2. User `bob` registers with the same password `secret`.
3. The two rows' `password` columns contain **different** bcrypt strings (different salts).
4. Both users can still log in successfully with `secret`.

---

## 7. Edge Cases

### EC-01: Legacy MD5 Row in Database

- The database file pre-dates this fix and contains a row whose `password` column is a 32-character MD5 hex digest (e.g. `5f4dcc3b5aa765d61d8327deb882cf99`).
- The user attempts to log in with the original plaintext.
- `auth_service.login()` fetches the row by username, then calls `verify_password(plain, "5f4dcc3b...")`.
- `bcrypt.checkpw` raises `ValueError("Invalid salt")`; the `try/except` swallows it and returns `False`.
- Server returns JSON 401. **The process does not crash.**

### EC-02: Empty Password Submitted

- `username=alice`, `password=""`.
- The early `if not username or not password` guard in `login()` returns JSON 401 before any hash operation. (Existing behavior preserved.)

### EC-03: Non-ASCII Password

- A user registers with password `pässwörd` (contains Latin-1 characters).
- `hash_password` encodes to UTF-8 bytes, bcrypt accepts them, hash is stored.
- The same user later logs in with `pässwörd` and is authenticated. The Latin-1 round-trip succeeds because both `hash_password` and `verify_password` use UTF-8 consistently (NFR-06).

### EC-04: Very Long Password

- A user registers with a 200-character password.
- Bcrypt truncates to the first 72 bytes silently (NFR-07).
- Login with the same 200-character string succeeds; login with the first 72 bytes of that string also succeeds (acceptable educational-context behavior).

### EC-05: Stored Hash is `NULL` or Empty String

- A malformed row where `password` is `NULL` or `""` is fetched.
- `verify_password(plain, None)` or `verify_password(plain, "")` calls bcrypt; `bcrypt.checkpw` raises; the `try/except` returns `False`.
- Server returns JSON 401. **The process does not crash.**

### EC-06: Bcrypt Module Not Installed

- If `bcrypt` is missing from the environment, `import bcrypt` at module load time raises `ModuleNotFoundError` and the application fails to start. This is the desired behavior — operators MUST `uv sync` to install the new dependency.

### EC-07: Concurrent Logins

- Two parallel login requests for the same user each perform their own bcrypt verify (≈ 250 ms each). The database fetch is independent; no shared state is mutated. Each request resolves correctly. (Documented for clarity; no code change is required.)

---

## 8. Acceptance Criteria

### AC-01: API Preserved

- `from app.core.security import hash_password, verify_password` still works after the change. Both functions have their original signatures (`(password: str) -> str` and `(plain: str, hashed: str) -> bool`).

### AC-02: New Hashes Are Bcrypt

- A freshly created user's `users.password` value begins with the literal prefix `$2b$`.
- The full string is 60 characters long.

### AC-03: Per-Call Salt

- `hash_password("p")` called twice in succession returns two **different** strings.
- Both strings, when passed back through `verify_password("p", h)`, return `True`.

### AC-04: Work Factor ≥ 12

- The hash's cost field (characters 4–6 of the bcrypt string, e.g. `$2b$12$...`) decodes to **≥ 12**.

### AC-05: Legacy MD5 Does Not Crash

- Manually inserting a row whose `password` is `5f4dcc3b5aa765d61d8327deb882cf99` (MD5 of `"password"`) and then attempting to log in as that user with `password=password` returns a JSON 401 — **not** a 500 — and the application keeps running.

### AC-06: Login Query Restructured

- The new login SQL contains `WHERE username = '<...>'` and **does not** include any `AND password = '...'` clause. The match-by-hash is gone from SQL.

### AC-07: SQL Injection Preserved (VULN-1)

- Submitting `username=admin' OR '1'='1' --` to `/login` still alters the SQL query structure (the `'1'='1'` tautology is still executable in the query string). The injection still allows authentication bypass when the fetched row's stored hash is bcrypt-comparable to the submitted password (or when any registered row is returned for the tautology and that row's password matches what the attacker supplied). The point is: **the SQL is still concatenated and still injectable** — fixing the injection is a separate task.

### AC-08: Other Vulnerabilities Preserved

- VULN-2 (Stored XSS) verifies: a user registered with username `<script>alert(1)</script>` still triggers script execution on `/welcome`.
- VULN-3 (Reflected XSS): `/search?q=<script>alert(1)</script>` still reflects the payload unescaped.
- VULN-4 (Session secret): the literal `"super-secret-key-12345"` is still present in `backend/app/main.py`.
- VULN-6 (Exposed DB): `GET /download/db` still serves the SQLite file unauthenticated.
- VULN-7 (No rate limit): no throttling middleware was added.
- VULN-8 (No CSRF): no CSRF token field was added to the login or signup form.

### AC-09: Dependency Recorded

- `grep '^bcrypt' backend/pyproject.toml` matches a `bcrypt>=4.0.0`-style line.
- `grep '"bcrypt' pyproject.toml` matches the same in the root manifest.

### AC-10: Migration Documented

- The verification steps (§10) include the explicit step "delete `vulnerable_app.db` OR re-register via `/signup`" before logging in, and this spec calls out that legacy MD5 accounts cannot authenticate after the fix.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Fresh signup writes bcrypt hash | Empty DB; bcrypt installed | Row's `password` column begins with `$2b$` and is 60 chars long |
| TC-02 | Same password, two users, different hashes | `alice` and `bob` both register with password `secret` | `alice.password != bob.password`; both strings start with `$2b$` |
| TC-03 | Both users can log in | TC-02 completed | Both `POST /login` calls return `{"success": true, "redirect": "/welcome"}` |
| TC-04 | Wrong password returns 401 | `alice` exists with password `secret` | `POST /login` with `password=WRONG` returns HTTP 401 and `{"error": "Invalid username or password"}` |
| TC-05 | Unknown username returns 401 | Any DB state | `POST /login` with `username=ghost` returns HTTP 401 |
| TC-06 | Work factor ≥ 12 | New signup | The cost portion of the bcrypt string (e.g. `$2b$12$`) decodes to integer ≥ 12 |
| TC-07 | Legacy MD5 row does not crash | Manually `INSERT INTO users (username, email, password) VALUES ('legacy', 'l@x', '5f4dcc3b5aa765d61d8327deb882cf99')` (MD5 of `"password"`) | `POST /login` as `legacy` with `password=password` returns HTTP 401, **server is still up**, and the next `/login` for a valid bcrypt user succeeds |
| TC-08 | NULL / empty hash row does not crash | Insert a row with `password=NULL` | Login attempt returns HTTP 401, server stays up |
| TC-09 | SQL injection still works (VULN-1 preserved) | At least one user `alice` in DB | `POST /login` with `username=alice' --` and any password — the trailing `--` truncates the rest of the SQL; the row for `alice` is fetched; if the submitted password matches `alice`'s real password, login succeeds. Demonstrates the username branch is still injectable. |
| TC-10 | Stored XSS still fires (VULN-2 preserved) | Register `<script>alert('xss')</script>`, log in | Visit `/welcome` → alert fires |
| TC-11 | Reflected XSS still fires (VULN-3 preserved) | App running | `curl /search?q=<script>alert(1)</script>` returns the payload unescaped in the body |
| TC-12 | Session secret unchanged (VULN-4 preserved) | App running | `grep 'super-secret-key-12345' backend/app/main.py` matches a line |
| TC-13 | `/download/db` still open (VULN-6 preserved) | App running | Unauthenticated `GET /download/db` returns HTTP 200 with a valid SQLite file body |
| TC-14 | No CSRF tokens added (VULN-8 preserved) | App running | `curl /login` and `curl /signup` HTML responses contain no `csrf_token` input field |
| TC-15 | Non-ASCII password round-trip | Empty DB | Register `username=u1`, `password=pässwörd`. Login with the same string succeeds; login with `passwoerd` fails (HTTP 401) |
| TC-16 | API import compatibility | Working virtualenv | `python -c "from app.core.security import hash_password, verify_password; print(hash_password('x')[:4])"` prints `$2b$` |
| TC-17 | Dependency declared in both manifests | Repo checkout | `grep -E '^\s*"?bcrypt' backend/pyproject.toml` and `grep -E '^\s*"?bcrypt' pyproject.toml` each match a line |
| TC-18 | Login SQL no longer matches on password | Inspect the query string built by `login()` (e.g. via a temporary `print`, or by reading the source) | The query string contains `WHERE username =` and does NOT contain `AND password =` |

---

## 10. Verification Steps

Run from the repository root.

### 10.1 Install the New Dependency

```bash
cd backend && uv sync && cd ..
```

Confirm `bcrypt` resolves and installs.

### 10.2 Reset the Database (Migration — FR-07)

```bash
rm -f vulnerable_app.db
```

This discards any legacy MD5-hashed accounts that would otherwise be unable to log in after the fix. The next application start re-runs `init_db()` and recreates an empty `users` table.

### 10.3 Start the Application

```bash
uv run backend/app/main.py
```

The server listens on `http://localhost:3001`.

### 10.4 Functional Walkthrough

1. **Register a user** — `http://localhost:3001/signup`
   - Submit `username=alice`, `email=alice@test.com`, `password=pass123`.
   - Expect a redirect to `/login`.
2. **Verify the stored hash is bcrypt** (AC-02, TC-01)
   ```bash
   sqlite3 vulnerable_app.db "SELECT password FROM users WHERE username='alice';"
   ```
   Expected: a 60-character string beginning with `$2b$12$`.
3. **Register a second user with the same password** (TC-02)
   - Submit `username=bob`, `email=bob@test.com`, `password=pass123`.
   ```bash
   sqlite3 vulnerable_app.db "SELECT username, password FROM users;"
   ```
   Expected: both `alice`'s and `bob`'s `password` strings begin with `$2b$12$` but are not equal to each other.
4. **Successful login** (TC-03) — `http://localhost:3001/login`
   - Submit `username=alice`, `password=pass123`.
   - Expect JSON `{"success": true, "redirect": "/welcome"}` and a working dashboard.
5. **Wrong password** (TC-04)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode 'username=alice' \
        --data-urlencode 'password=WRONG'
   ```
   Expected: HTTP 401, body `{"error":"Invalid username or password"}`.
6. **Unknown username** (TC-05)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode 'username=ghost' \
        --data-urlencode 'password=x'
   ```
   Expected: HTTP 401.

### 10.5 Legacy MD5 Row Test (AC-05, TC-07)

```bash
sqlite3 vulnerable_app.db "INSERT INTO users (username, email, password) VALUES ('legacy', 'l@x', '5f4dcc3b5aa765d61d8327deb882cf99');"
curl -s -i -X POST http://localhost:3001/login \
     --data-urlencode 'username=legacy' \
     --data-urlencode 'password=password'
```

Expected: HTTP 401 with the standard error JSON. The server log shows no traceback. A subsequent login for `alice` (TC-03) still succeeds — the process is still healthy.

### 10.6 Vulnerability Preservation Walkthrough

```bash
# VULN-1: SQL injection still possible on the username branch (TC-09)
curl -s -i -X POST http://localhost:3001/login \
     --data-urlencode "username=alice' --" \
     --data-urlencode 'password=pass123'
# Expected: HTTP 200 with success JSON — the `--` truncates the SQL after the username, alice's row is returned, and her real password verifies.

# VULN-2: Stored XSS still fires (TC-10)
curl -s -i -X POST http://localhost:3001/signup \
     --data-urlencode 'username=<img src=x onerror=alert(1)>' \
     --data-urlencode 'email=xss@x' \
     --data-urlencode 'password=p'
# Then log in as that user and visit /welcome in a browser — the alert fires.

# VULN-3: Reflected XSS (TC-11)
curl -s 'http://localhost:3001/search?q=<script>alert(1)</script>' | grep -o '<script>alert(1)</script>'

# VULN-4: Session secret unchanged (TC-12)
grep -n 'super-secret-key-12345' backend/app/main.py

# VULN-6: /download/db still open (TC-13)
curl -s -o /tmp/dl.db -w 'status=%{http_code} bytes=%{size_download}\n' http://localhost:3001/download/db
file /tmp/dl.db

# VULN-8: No CSRF tokens (TC-14)
curl -s http://localhost:3001/login  | grep -i csrf || echo '(no csrf field — preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo '(no csrf field — preserved)'
```

### 10.7 API Import Smoke Test (TC-16)

```bash
cd backend && uv run python -c "from app.core.security import hash_password, verify_password; h = hash_password('x'); print(h[:4], verify_password('x', h), verify_password('y', h))"
```

Expected: prints `$2b$ True False`.

### 10.8 Dependency Manifests (TC-17, AC-09)

```bash
grep -E '^\s*"?bcrypt' backend/pyproject.toml
grep -E '^\s*"?bcrypt' pyproject.toml
```

Expected: each command prints a single matching line.

### 10.9 Affected-Files Audit

```bash
git status --porcelain
```

Expected output — exactly four modified files:

```
 M backend/app/core/security.py
 M backend/app/services/auth_service.py
 M backend/pyproject.toml
 M pyproject.toml
```

(`uv.lock` may also appear as a regenerated lock artifact; that is acceptable per FR-06.)

---

## 11. Migration & Operational Note

After deploying this change, any database row whose `password` column is a 32-character hex string (an MD5 digest left over from before the fix) is **no longer authenticatable**. There is no automatic upgrade-on-login path — the spec deliberately rejects "rehash on successful login" because that would require the user to log in once with a hash that this code refuses to validate, which is impossible by design.

Operators have exactly two safe paths:

1. **Reset the lab DB**: `rm vulnerable_app.db && uv run backend/app/main.py` — `init_db()` recreates an empty schema. All accounts re-register from scratch. This is the recommended path for the educational lab.
2. **Re-register**: tell affected users to visit `/signup` and create a new account. Their old row remains in the table but is unreachable; they pick a new username or the operator manually deletes the old row.
