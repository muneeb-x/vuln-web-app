# Implementation Plan — Reflected XSS Fix (`/search` Query Escaping)

**Version:** 1.0.0
**Last Updated:** June 15, 2026
**Parent Spec:** [reflected-xss-fix.md](./reflected-xss-fix.md)
**Foundation Spec:** [app-foundation.md](./app-foundation.md)
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)
**Tracking Issue:** [Reflected XSS — unescaped `q` reflection in `/search`](https://github.com/arifpucit/vuln-web-app/issues)

---

## 0. Plan Overview

This plan implements the fix specified in [reflected-xss-fix.md](./reflected-xss-fix.md). It closes the **Reflected XSS** vulnerability and **only** that vulnerability, by routing every attacker-controllable value spliced into the `/search` response through `html.escape(..., quote=True)`. The three sinks inside `search_user` are:

1. The reflected `q` in the `<h3>Search results for: …</h3>` heading.
2. The `row[0]` and `row[1]` columns in each `<li>…</li>` result item.
3. The `str(e)` text in the `<h3>Error: …</h3>` response from the `except` branch.

The standard-library `html` module is **already imported** at the top of `backend/app/api/routes/auth.py` (added by the VULN-2 fix). No new import is added; the existing one is reused. The work is split into **three phases** so the change is small, individually verifiable, and easy to revert.

The other intentional vulnerabilities (No Rate Limiting, CSRF) MUST remain exploitable after every phase, and the already-closed fixes (bcrypt password hashing, parameterized SQL, removed `/download/db`, env-sourced session secret, escaped dashboard `{{username}}`) stay closed. Each phase ends with an explicit "MUST NOT" callout listing things that would silently alter another vulnerability.

### Phase Summary

| # | Phase | Files Touched | Goal |
|---|-------|--------------|------|
| 1 | Apply the edits in `search_user` inside `auth.py` | `backend/app/api/routes/auth.py` | Escape `q`, each row column, and the exception text before splicing into responses |
| 2 | End-to-end verification | None (read-only) | Walk every Verification Step in spec §10 |
| 3 | Vulnerability preservation audit | None (read-only) | Confirm the other vulnerabilities behave as specified |

### Files Modified (Authored)

Exactly the one source file declared in spec §3:

- `backend/app/api/routes/auth.py`

No dependency change (`html` is in the Python standard library and is already imported), so no `pyproject.toml` or `uv.lock` edit (and no `uv sync`).

### Files That MUST NOT Be Modified

- `backend/app/main.py` — preserves the env-sourced session secret (VULN-4 stays closed).
- `backend/app/services/auth_service.py` — preserves parameterized queries (VULN-1 stays closed) and bcrypt verification call (VULN-5 stays closed); the signup/login flow MUST continue to store the raw, unsanitized values of `username` and `email` (per spec §FR-05 / §FR-08 — output-encoding fix, not input filtering).
- `backend/app/core/security.py` — bcrypt stays; do not revert.
- `backend/app/db/session.py` — schema and connection layer; untouched.
- `frontend/templates/dashboard.html` — the `{{username}}` placeholder, the surrounding `<strong>` element, and every other character stay byte-for-byte; the VULN-2 escape happens server-side in `welcome_page` and the template requires no change.
- `frontend/templates/login.html`, `frontend/templates/signup.html` — no template-side change.
- Any CSS under `frontend/static/`.
- `CLAUDE.md`, `README.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, and every other prior spec.
- `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` (no dependency change — `html` is stdlib and is already imported by the VULN-2 fix).

### Vulnerability Preservation Checklist (Carry Through Every Phase)

After the edit, re-confirm:

1. **SQL Injection.** Already CLOSED — `auth_service.py` uses parameterized queries (`WHERE username = ?`, `VALUES (?, ?, ?)`) and `/search` uses `SELECT … WHERE username LIKE ? OR email LIKE ?` with `?` bindings. **Stays closed.** This plan MUST NOT change the SQL string, the parameter bindings, or the wrapping of `q` as `f"%{q}%"` for the LIKE pattern. HTML escaping is applied to the response-rendering value only, never to the SQL bind value.
2. **Stored XSS.** Already CLOSED — `welcome_page` escapes `username` via `html.escape(..., quote=True)` before substitution. Not touched; stays closed.
3. **Reflected XSS.** **This is the only vulnerability being closed.** After Phase 1, the three `/search` sinks (heading, list items, error response) all render attacker-controllable values as inert text.
4. **Session Hijacking.** Already CLOSED — `main.py` sources `SECRET_KEY` from the environment with a `secrets.token_hex(32)` fallback. Not touched; stays closed.
5. **Weak Password (bcrypt).** `security.py` still uses bcrypt at rounds ≥ 12 with the defensive `try/except` in `verify_password`. Not touched; stays closed.
6. **Exposed Database endpoint.** Already CLOSED — `/download/db` route removed. Not touched; stays closed.
7. **No Rate Limiting.** No throttling middleware, per-IP counter, or `time.sleep` added — not touched.
8. **CSRF.** No CSRF token field or middleware added — not touched.

---

## Phase 1 — Apply the Edits in `search_user`

### 1.1 Goal

Inside `search_user` (and only inside `search_user`), route the reflected `q`, each result-row column, and the exception text through `html.escape(..., quote=True)` before splicing them into HTML responses. The SQL layer is untouched. All edits are confined to `backend/app/api/routes/auth.py`.

### 1.2 File to Modify

- `backend/app/api/routes/auth.py`

### 1.3 Edit A — No New Import

The top of the file already reads:

```python
import os
import html
```

`import html` was added by the VULN-2 fix and is reused here. **Do not** add another `import html`; **do not** remove or reorder the existing imports. Phase 1 verification grep confirms there is exactly one `^import html$` line.

**Naming caveat — IMPORTANT.** Unlike `welcome_page` (which previously had a local `html` variable that had to be renamed to `page` when the module-level `import html` was introduced), `search_user`'s current body uses a local variable named `html` to hold the rendered response string. After the existing module-level `import html` is in scope, that local variable shadows the module — so `html.escape(...)` inside the function would raise `AttributeError: 'str' object has no attribute 'escape'`. The rename is therefore part of the fix, not an aesthetic cleanup.

### 1.4 Edit B — Escape Every Sink in `search_user`

The current handler (L53–76) reads:

```python
@router.get("/search")
async def search_user(q: str = ""):
    if not q:
        return HTMLResponse(content="<h3>No search query provided</h3>")

    # FIXED: SQL Injection closed by using parameterized query
    # VULNERABILITY #3: Reflected XSS still preserved -- query interpolated into HTML without escaping
    query = "SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?"

    conn = get_db()
    try:
        cursor = conn.execute(query, [f"%{q}%", f"%{q}%"])
        rows = cursor.fetchall()

        results = ""
        for row in rows:
            results += f"<li>{row[0]} ({row[1]})</li>"

        html = f"<h3>Search results for: {q}</h3><ul>{results}</ul>"
        return HTMLResponse(content=html)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error: {str(e)}</h3>")
    finally:
        conn.close()
```

**After** — replace the entire `search_user` body with:

```python
@router.get("/search")
async def search_user(q: str = ""):
    if not q:
        return HTMLResponse(content="<h3>No search query provided</h3>")

    # FIXED: SQL Injection closed by using parameterized query
    # FIXED: Reflected XSS closed -- q, row columns, and exception text are HTML-escaped before splicing.
    # The raw values remain in the URL and in the database (output-encoding fix, not input filtering).
    query = "SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?"

    conn = get_db()
    try:
        cursor = conn.execute(query, [f"%{q}%", f"%{q}%"])
        rows = cursor.fetchall()

        safe_q = html.escape(q, quote=True)
        results = ""
        for row in rows:
            safe_username = html.escape(row[0], quote=True)
            safe_email = html.escape(row[1], quote=True)
            results += f"<li>{safe_username} ({safe_email})</li>"

        page = f"<h3>Search results for: {safe_q}</h3><ul>{results}</ul>"
        return HTMLResponse(content=page)
    except Exception as e:
        safe_error = html.escape(str(e), quote=True)
        return HTMLResponse(content=f"<h3>Error: {safe_error}</h3>")
    finally:
        conn.close()
```

Six concrete changes inside the handler:

1. The two-line comment block updated from "VULNERABILITY #3: …" to "FIXED: Reflected XSS closed …" (the "FIXED: SQL Injection closed …" line stays — VULN-1 was already closed and is not touched here).
2. `safe_q = html.escape(q, quote=True)` computed once before the heading interpolation.
3. Inside the `for row in rows:` loop, `safe_username = html.escape(row[0], quote=True)` and `safe_email = html.escape(row[1], quote=True)` computed per row.
4. The list-item interpolation changes from `f"<li>{row[0]} ({row[1]})</li>"` to `f"<li>{safe_username} ({safe_email})</li>"`.
5. `html = f"<h3>Search results for: {q}</h3><ul>{results}</ul>"` → `page = f"<h3>Search results for: {safe_q}</h3><ul>{results}</ul>"`. The local rename (`html` → `page`) frees the `html` name for the module reference; the heading interpolation uses the escaped value.
6. `return HTMLResponse(content=html)` → `return HTMLResponse(content=page)`. In the `except` branch, `safe_error = html.escape(str(e), quote=True)` is computed and used in `f"<h3>Error: {safe_error}</h3>"`.

The early `if not q:` short-circuit (returning the static `<h3>No search query provided</h3>` body) is **unchanged byte-for-byte**. The SQL string and its `[f"%{q}%", f"%{q}%"]` bindings are **unchanged byte-for-byte** — the raw `q` (NOT `safe_q`) is what reaches the parameterized `LIKE ?` bind, preserving VULN-1 closure at the SQL boundary independently of the HTML escaping. The `try` / `except` / `finally` structure and the `conn.close()` call in the `finally` block are preserved.

### 1.5 Edit Summary

Edits inside `auth.py`, all confined to `search_user`:

1. **Top of file** — no change. The existing `import html` (added by VULN-2) is reused.
2. **`search_user` (L53–76)** — update the comment block, compute `safe_q` once, compute per-row `safe_username` / `safe_email`, rename the local `html` variable to `page`, and add `safe_error = html.escape(str(e), quote=True)` in the `except` branch.

No other line in the file changes. `index`, `signup_page`, `signup_post`, `login_page`, `login_post`, `welcome_page`, and `logout` are all untouched — in particular, `welcome_page`'s `html.escape(username, quote=True)` substitution stays exactly as it stands (preserves VULN-2 closure).

### 1.6 Line-by-Line Justification

| Line / Block | Decision | Spec ref |
|---|---|---|
| Existing `import html` reused (no second import) | The module is already in scope from the VULN-2 fix | FR-07, NFR-06 |
| Rename local `html` → `page` in `search_user` | Prevents the local shadowing the imported module; the only way `html.escape(...)` resolves correctly inside this function | FR-01, NFR-03 |
| `safe_q = html.escape(q, quote=True)` | Required: escape the reflected query before the heading interpolation | FR-01, FR-04, AC-02, AC-06 |
| Per-row `safe_username = html.escape(row[0], quote=True)` and `safe_email = html.escape(row[1], quote=True)` | Required: each list item is an independent sink for attacker-controllable column data | FR-02, AC-03, SP-05 |
| `safe_error = html.escape(str(e), quote=True)` | Required: the `except` branch is a third sink that can echo attacker-shaped fragments from driver exceptions | FR-03, AC-04, EC-05 |
| `quote=True` on every call | Quote-aware escaping protects against attribute-context regressions | FR-04, NFR-01, SP-04 |
| SQL string and `[f"%{q}%", f"%{q}%"]` bindings unchanged | The SQL parameterized-`?` defense stays the sole defense at the SQL boundary; HTML escaping must not bleed into the bind value | FR-05, NFR-08, AC-05 |
| `if not q:` short-circuit unchanged | The static literal has no attacker input | FR-06, EC-02, EC-03, AC-10 |
| `try` / `except` / `finally` structure and `conn.close()` unchanged | Connection lifecycle is preserved | FR-10, EC-06 |
| `HTMLResponse(content=…)` return type / status / content type unchanged | API stability | NFR-03, NFR-05, FR-09 |
| `welcome_page` body untouched | Preserves VULN-2 closure (`html.escape(username, quote=True)` stays) | FR-08, AC-11 |
| `auth_service.signup()` / `login()` untouched | Database and session still hold raw payloads; preserves educational lesson | FR-05, FR-08, EC-01, AC-13 |

### 1.7 What NOT to Change in Phase 1

- **DO NOT** escape `q` before binding it into the SQL LIKE clause. The bind value MUST stay as `f"%{q}%"` (raw). Escaping the SQL bind would corrupt searches that legitimately contain HTML-meaningful characters and conflates two independent defenses; spec §FR-05 and §NFR-08 forbid it.
- **DO NOT** change the SQL string. It stays exactly `SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?`. No column added, no removed, no concatenation reintroduced.
- **DO NOT** modify the `if not q:` short-circuit. The static literal `<h3>No search query provided</h3>` is not attacker-controlled and stays byte-for-byte (spec §FR-06, AC-10).
- **DO NOT** add a second `import html`. Reuse the existing one. A duplicate import would not break correctness, but it would fail the "single matching line" expectation in spec §10.1 and would be flagged by the affected-files audit.
- **DO NOT** remove the existing `import html`. It is still needed by `welcome_page`.
- **DO NOT** touch `welcome_page`. The escape call there is the VULN-2 closure and stays exactly as it stands (spec §FR-08, AC-11).
- **DO NOT** sanitize username or email in `auth_service.signup()` or `auth_service.login()`. The INSERT must still write the raw values to `users.username` and `users.email`, and the session write must still copy the raw `users.username`. The fix is **output encoding at the sink**, not input filtering (spec §FR-05, §FR-08, EC-01, AC-13).
- **DO NOT** add `bleach`, `MarkupSafe`, Jinja2, or any other third-party dependency. The spec mandates standard-library-only (spec §FR-07, §NFR-06). No `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` edit; no `uv sync`.
- **DO NOT** switch to a template engine. The handler stays plain f-string concatenation; only the values being inserted are escaped.
- **DO NOT** drop the `quote=True` argument on any call. The spec requires quote-aware escaping so the fix remains correct even if a future maintainer moves the reflected value into an HTML attribute (spec §FR-04).
- **DO NOT** add a length cap on `q`, on row columns, or on the exception text. Spec §EC-09 explicitly notes there is no length cap.
- **DO NOT** narrow the `except Exception as e` clause. The set of exceptions caught is unchanged; only the rendering of `str(e)` is escaped (spec §NFR-05).
- **DO NOT** change HTTP status codes, headers, response timing, or log lines on `/search` (spec §NFR-03, §NFR-05).
- **DO NOT** touch `main.py`, `services/auth_service.py`, `core/security.py`, `db/session.py`, or any CSS / template file.
- **DO NOT** re-introduce a closed vulnerability:
  - No re-adding `/download/db` (VULN-6 stays closed).
  - No reverting `main.py` to the hardcoded `"super-secret-key-12345"` (VULN-4 stays closed).
  - No reverting `security.py` to MD5 (VULN-5 stays closed).
  - No reverting `auth_service.py` to string-concatenated SQL (VULN-1 stays closed).
  - No removing the `html.escape` call inside `welcome_page` (VULN-2 stays closed).

### 1.8 Phase 1 Verification (Pre-Server)

```bash
# Import still present and singular (no second copy added, no copy removed)
test "$(grep -c '^import html$' backend/app/api/routes/auth.py)" = "1" \
  && echo '(import html still present, single line)'

# Escape on substitution present — at least four matches total:
#   - one inside welcome_page (existing, from VULN-2)
#   - three new ones inside search_user (q, row columns, str(e))
grep -n 'html.escape(' backend/app/api/routes/auth.py

# Raw `q` reflection removed from the heading
grep -n 'Search results for: {q}' backend/app/api/routes/auth.py \
  || echo '(raw q reflection removed from heading)'

# Raw row-column reflection removed from the list items
grep -n '<li>{row\[0\]} ({row\[1\]})</li>' backend/app/api/routes/auth.py \
  || echo '(raw row-column reflection removed)'

# Raw exception reflection removed from the error response
grep -n 'Error: {str(e)}' backend/app/api/routes/auth.py \
  || echo '(raw exception reflection removed)'

# Local rename applied — no leftover `html = f"<h3>Search results` (which would AttributeError at runtime
# the moment any code in this function calls html.escape)
grep -n 'html = f"<h3>Search results' backend/app/api/routes/auth.py \
  || echo '(no shadowing local html assignment left)'

# SQL string and bindings unchanged — VULN-1 stays closed at the SQL boundary
grep -n 'WHERE username LIKE ? OR email LIKE ?' backend/app/api/routes/auth.py
grep -n '\[f"%{q}%", f"%{q}%"\]' backend/app/api/routes/auth.py

# welcome_page escape stays — VULN-2 stays closed
grep -n 'html.escape(username, quote=True)' backend/app/api/routes/auth.py

# Module imports cleanly under the runtime Python
cd backend && uv run python -c "from app.api.routes.auth import router; print('import ok')" && cd ..
```

Expected: the first `test` prints `(import html still present, single line)`; the `html.escape(` grep returns at least four matches (one in `welcome_page`, three in `search_user`); the four "raw … reflection removed" greps each print their fallback; the shadowed-local grep prints its fallback; the SQL-string and bindings greps both match; the `welcome_page` escape grep matches; the import smoke test prints `import ok`.

---

## Phase 2 — End-to-End Verification

This phase walks every Verification Step in spec §10 in order. **No edits** are made; if any step fails, return to Phase 1 to repair.

### 2.1 Start the Application (spec §10.3 — AC-15, TC-21)

```bash
rm -f vulnerable_app.db
uv run backend/app/main.py
```

The DB reset is recommended so the test users registered below have predictable bcrypt hashes and a clean `users` table — pre-existing rows still work, but a fresh DB keeps the walkthrough reproducible. The server listens on `http://localhost:3001` with no import/boot error.

### 2.2 Confirm the Import is Present and Singular (spec §10.1 — AC-01, TC-01)

```bash
grep -cn '^import html$' backend/app/api/routes/auth.py
```

Expected: `1` (a single matching line near the top of the file; not removed, not duplicated).

### 2.3 Confirm Escape on the Reflected `q`, on the Row Columns, and on the Exception (spec §10.2 — AC-02–AC-04, TC-02–TC-04)

```bash
grep -n 'html.escape(' backend/app/api/routes/auth.py
```

Expected: at least four matching lines — one inside `welcome_page` (escaping `username`, from VULN-2) and three inside `search_user` (escaping `q`, escaping each row column, escaping `str(e)`). Manual inspection confirms the escaped values are what reach the `f"…{…}…"` interpolations and that no raw `q`, raw `row[0]`/`row[1]`, or raw `str(e)` remains in any `HTMLResponse(content=…)` call.

### 2.4 Benign Query Round-Trip (spec §10.4 — AC-09, TC-05)

```bash
curl -s 'http://localhost:3001/search?q=alice' | grep -o '<h3>Search results for: alice</h3>'
```

Expected: the literal heading is printed verbatim (no entity encoding — `html.escape` is a no-op on plain alphanumeric input).

### 2.5 `<script>` Payload Reflected Inert (spec §10.5 — AC-07, TC-06)

```bash
BODY=$(curl -s 'http://localhost:3001/search?q=<script>alert(1)</script>')
echo "$BODY" | grep -o '&lt;script&gt;alert(1)&lt;/script&gt;' && echo 'escaped: OK'
echo "$BODY" | grep -c '<h3>Search results for: <script>alert(1)</script></h3>'
```

Expected: the escaped substring is found (prints `escaped: OK`); the live-`<script>` form inside the heading is **not** found (count is `0`).

### 2.6 `<img onerror>` Payload Reflected Inert (spec §10.6 — AC-08, TC-07)

```bash
curl -s 'http://localhost:3001/search?q=<img src=x onerror=alert(1)>' \
  | grep -o '&lt;img src=x onerror=alert(1)&gt;'
```

Expected: the escaped substring is printed.

### 2.7 Attribute-Breakout Payload Neutralized (spec §10.7 — AC-06, TC-08)

```bash
curl -s 'http://localhost:3001/search?q=%22%20onmouseover=alert(1)%20x=%22' | grep -o '&quot;'
```

Expected: the `&quot;` entity is printed (confirms `quote=True` is in effect).

### 2.8 Result-Row Payload Reflected Inert (spec §10.8 — SP-05, TC-10)

```bash
curl -s -c xss_jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=<script>alert(1)</script>' \
     --data-urlencode 'email=xss@x' \
     --data-urlencode 'password=p'
curl -s 'http://localhost:3001/search?q=script' | grep -o '<li>&lt;script&gt;alert(1)&lt;/script&gt;'
```

Expected: a list item containing the escaped form is printed; no live `<script>` tag is rendered inside any `<li>`.

### 2.9 Empty-Query Short-Circuit Unchanged (spec §10.9 — AC-10, TC-11)

```bash
curl -s 'http://localhost:3001/search'    | diff - <(printf '%s' '<h3>No search query provided</h3>')
curl -s 'http://localhost:3001/search?q=' | diff - <(printf '%s' '<h3>No search query provided</h3>')
```

Expected: both `diff` invocations produce no output (byte-for-byte match against the static literal).

### 2.10 Stored Data Still Malicious (spec §10.10 — AC-13, TC-22)

```bash
sqlite3 vulnerable_app.db "SELECT username FROM users WHERE username LIKE '<script>%';"
```

Expected: returns the raw `<script>alert(1)</script>` string — confirming the fix is output encoding at the sink, not input filtering. The database still holds the raw payload (per spec §FR-05 / §FR-08).

### 2.11 Dashboard Escaping Preserved (spec §10.11 — AC-11, TC-13)

```bash
# Reuse the cookie jar from §2.8 (xss_jar.txt) to log in as the malicious-username user
curl -s -c xss_jar.txt -b xss_jar.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=<script>alert(1)</script>' \
     --data-urlencode 'password=p'
curl -s -b xss_jar.txt http://localhost:3001/welcome | grep -o '&lt;script&gt;alert(1)&lt;/script&gt;'
```

Expected: the escaped substring is printed (VULN-2 closure intact — the dashboard `{{username}}` escape is unaffected by this fix).

### 2.12 Affected-Files Audit (spec §10.13 — AC-14, TC-20)

```bash
git status --porcelain
```

Expected output — exactly one modified source file plus the two new spec docs:

```
 M backend/app/api/routes/auth.py
?? .claude/specs/reflected-xss-fix.md
?? .claude/specs/reflected-xss-fix-plan.md
```

No other path. In particular, no entry for `main.py`, `auth_service.py`, `security.py`, `db/session.py`, any template, any CSS file, or any pyproject/lock file.

---

## Phase 3 — Vulnerability Preservation Audit

Read-only confirmation that the other intentional vulnerabilities still fire (VULN-7, VULN-8) and that the already-closed ones stay closed (VULN-1, VULN-2, VULN-4, VULN-5, VULN-6). Mirrors spec §10.12.

### 3.1 VULN-1 SQL Injection Stays Closed (AC-12, TC-14)

```bash
grep -n 'WHERE username = ?' backend/app/services/auth_service.py
grep -n 'LIKE ?' backend/app/api/routes/auth.py
```

Expected: both parameterized-query patterns match. No regression to string-concatenated SQL. The `/search` SQL string and bindings are exactly as Phase 1.4 specifies — the raw `q` is wrapped as `f"%{q}%"` and bound positionally.

### 3.2 VULN-2 Stored XSS Stays Closed (AC-11, TC-13)

```bash
grep -n 'html.escape(username, quote=True)' backend/app/api/routes/auth.py
```

Expected: the call inside `welcome_page` is still present. Runtime check at §2.11 confirms it still escapes a `<script>` username on the dashboard.

### 3.3 VULN-4 Session Secret Stays Env-Sourced (AC-12, TC-15)

```bash
grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py
grep -n 'super-secret-key-12345' backend/app/main.py \
  || echo '(hardcoded secret absent — preserved)'
```

Expected: the `os.environ.get("SECRET_KEY"` line is present; the literal `super-secret-key-12345` does NOT appear. The fallback uses `secrets.token_hex(32)`.

### 3.4 VULN-5 Bcrypt Stays in Use (AC-12, TC-16)

```bash
grep -n 'bcrypt' backend/app/core/security.py
```

Expected: bcrypt is still imported and used. No reversion to MD5.

### 3.5 VULN-6 `/download/db` Stays Removed (AC-12, TC-17)

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/download/db
```

Expected: `404`. The route stays absent from the router.

### 3.6 VULN-7 No Rate Limiting (AC-12, TC-18)

```bash
for i in {1..50}; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
       --data-urlencode 'username=ghost' --data-urlencode "password=$i"
done | sort -u
```

Expected: only `401` appears in the deduplicated output — no `429`, no connection refusals, no throttling.

### 3.7 VULN-8 No CSRF Tokens (AC-12, TC-19)

```bash
curl -s http://localhost:3001/login  | grep -i csrf || echo '(no csrf field — preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo '(no csrf field — preserved)'
```

Expected: each command prints the `(no csrf field — preserved)` fallback. No CSRF token field, no CSRF middleware.

### 3.8 Spec Acceptance Criteria Roll-Up

Tick every AC from spec §8:

- [ ] AC-01 `html` Module Still Imported (Phase 1.3, Phase 2.2)
- [ ] AC-02 Reflected `q` Escaped Before Splicing (Phase 1.4, Phase 2.3, Phase 2.5)
- [ ] AC-03 Result Rows Escaped Before Splicing (Phase 1.4, Phase 2.3, Phase 2.8)
- [ ] AC-04 Exception Text Escaped Before Splicing (Phase 1.4, Phase 2.3)
- [ ] AC-05 SQL Query Unchanged (Phase 1.4, Phase 1.8, Phase 3.1)
- [ ] AC-06 Quote-Aware Escaping in Use (Phase 1.4 `quote=True`, Phase 2.7)
- [ ] AC-07 `<script>` Query Reflected as Text (Phase 2.5)
- [ ] AC-08 `<img onerror>` Query Reflected as Text (Phase 2.6)
- [ ] AC-09 Benign Queries Unchanged (Phase 2.4)
- [ ] AC-10 Empty-Query Short-Circuit Unchanged (Phase 2.9)
- [ ] AC-11 Dashboard Escaping Preserved (VULN-2) (Phase 2.11, Phase 3.2)
- [ ] AC-12 Other Vulnerabilities Preserved (Phase 3.1, Phase 3.3–3.7)
- [ ] AC-13 Stored Data Untouched (Phase 2.10)
- [ ] AC-14 Only `auth.py` Modified (Phase 2.12)
- [ ] AC-15 Application Boots (Phase 2.1, Phase 1.8 import smoke test)

### 3.9 Stop the Server

`Ctrl+C` to stop. Plan complete.

---

## Risk Log & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Local variable `html` shadows the imported `html` module inside `search_user` → `AttributeError: 'str' object has no attribute 'escape'` on the first request that reaches an `html.escape(...)` call | Medium | High | Phase 1.4 explicitly renames the local to `page`; Phase 1.8 import smoke test surfaces the issue early; Phase 1.8 sixth grep (`html = f"<h3>Search results`) catches a leftover shadowed assignment; Phase 2.5 round-trip catches it at runtime |
| Forgetting `quote=True` on one of the three escape calls — attribute-breakout payloads still execute if any sink is ever moved into an attribute | Low | Medium | Spec §FR-04 + Phase 1.4 edit shows the literal call with `quote=True` on every site; Phase 2.7 curl + grep verifies `&quot;` is present in the rendered response |
| Escaping `q` for the SQL bind value as well as the HTML reflection — silently breaks legitimate searches that contain HTML-meaningful characters AND conflates two independent defenses | Medium | Medium | Spec §FR-05, §NFR-08 + Phase 1.7 "MUST NOT" explicitly forbid escaping the bind; Phase 1.8 grep asserts `[f"%{q}%", f"%{q}%"]` is unchanged; Phase 3.1 confirms the LIKE pattern still matches |
| Missing one of the three sinks — e.g. escaping `q` but forgetting the `row[i]` columns or the `str(e)` exception text | Medium | High | Spec §FR-01/§FR-02/§FR-03 enumerate all three; Phase 1.8 dedicated greps for each raw form; Phase 2.5 / 2.6 / 2.8 exercise each sink at runtime; the `html.escape(` grep in Phase 2.3 must show at least four matches (1 existing + 3 new) |
| Sanitizing on input (in `auth_service.signup()`) instead of output — closes XSS but loses the educational demonstration and changes a file outside the declared scope | Medium | Medium | Spec §FR-05/§FR-08 + Phase 1.7 MUST-NOT explicitly forbid touching `auth_service.py`; Phase 2.10 sqlite check confirms raw payload is still stored; Phase 2.12 file audit catches the stray edit |
| Switching to a template engine (Jinja2, MarkupSafe) "while in here" — scope creep + dependency change | Low | Medium | Spec §FR-07 + Phase 1.7 MUST-NOT forbid new deps; Phase 2.12 file audit catches stray pyproject/lock edits |
| Accidentally narrowing `except Exception as e` to a specific exception class — would change which errors are surfaced and could alter response timing | Low | Low | Phase 1.7 MUST-NOT explicitly preserves the broad `except`; Phase 1.4 shows the unchanged clause; behavior is unchanged on the success path |
| Accidentally re-opening a previously closed vulnerability while editing `auth.py` (e.g. re-adding `/download/db`, removing the `welcome_page` escape) | Very Low | High | Phase 1.7 MUST-NOT enumerates all closed vulns; Phase 3.1–3.5 grep/curl checks per closed vuln catch any regression; the `welcome_page`-escape grep in Phase 3.2 is the explicit guard against silently undoing VULN-2 |
| Duplicating the `import html` line | Very Low | Low | Phase 1.3 explicitly says "no new import"; Phase 1.8 first check asserts the line count is exactly 1 |
| (Fallback) Implementer rejects the local-variable rename for style reasons | Low | Low | Spec §FR-07 still allows an aliased import as an alternative: `from html import escape as html_escape`, keeping the local `html` name; only the call sites change (`html_escape(q, quote=True)`, etc.). Option 1 (rename to `page`) remains the recommended path. |

---

## Rollback Procedure

If a phase fails verification and cannot be repaired quickly:

```bash
git restore backend/app/api/routes/auth.py
```

The single authored file snaps back to its pre-fix state. No dependency, schema, or data migration is involved — the `vulnerable_app.db` file, the `users` table, and the session cookie format are all untouched by the fix in the first place.

---

## Out-of-Band: What This Plan Deliberately Does NOT Do

To make the negative space explicit:

- **No input filtering or sanitization.** The signup/login flow still writes the raw, unsanitized `username` and `email` into `users.username` / `users.email`. The `q` query parameter is still bound raw into the SQL LIKE pattern. Malicious payloads are still **stored** and still **reflected through the SQL layer**; they are merely rendered inert at the three `/search` output sinks. This preserves the educational lesson that the correct mitigation is output encoding at every sink, not "wash the data once at the source."
- **No SQL change.** The SQL string and its `?` parameter bindings are byte-for-byte unchanged. VULN-1 closure at the SQL boundary is independent of the HTML escaping added here.
- **No template-engine adoption.** No Jinja2, no MarkupSafe, no auto-escape framework. The handler stays plain f-string concatenation; only the values being inserted are escaped.
- **No template edits.** `dashboard.html`, `login.html`, and `signup.html` are byte-for-byte unchanged. The `/search` response is server-rendered inline inside `search_user` and has no template file at all.
- **No change to `welcome_page`.** The VULN-2 closure (`html.escape(username, quote=True)`) stays exactly as it stands. The newly-added escapes are confined to `search_user`.
- **No change to rate-limiting posture.** VULN-7 remains. No throttling middleware is added.
- **No change to CSRF posture.** VULN-8 remains. No CSRF tokens are added to forms; no CSRF middleware is registered.
- **No reversal of prior fixes.** VULN-1 (parameterized SQL), VULN-2 (escaped `{{username}}`), VULN-4 (env-sourced session secret), VULN-5 (bcrypt), and VULN-6 (removed `/download/db`) all stay closed.
- **No new dependency.** `html` is a Python standard-library module and is already imported by the VULN-2 fix; `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are not edited; no `uv sync` is required.
- **No database migration.** The `users` table schema, the existing rows, and the on-disk `vulnerable_app.db` file are unchanged. Pre-existing accounts (including any whose `username` or `email` column already contains malicious markup) continue to work without modification — their payloads simply render as inert text in `/search` result lists and on `/welcome`.
- **No file** created or modified beyond `backend/app/api/routes/auth.py` and this spec/plan pair.
