# Software Specification Document — Reflected XSS Fix (`/search` Query Escaping)

**Version:** 1.0.0
**Last Updated:** June 15, 2026
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [Reflected XSS — unescaped `q` reflection in `/search`](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the remediation of the **Reflected XSS** vulnerability (OWASP **A03:2021 — Injection**). In `backend/app/api/routes/auth.py` the `search_user` handler reads the `q` query-string parameter and splices it directly into the response HTML — both into the heading line and into any error response — without HTML-escaping:

```python
# VULNERABILITY #3: Reflected XSS still preserved -- query interpolated into HTML without escaping
...
html = f"<h3>Search results for: {q}</h3><ul>{results}</ul>"
return HTMLResponse(content=html)
...
return HTMLResponse(content=f"<h3>Error: {str(e)}</h3>")
```

The `q` value originates from the URL of the current request, so an attacker who crafts a link such as `http://localhost:3001/search?q=<script>alert(1)</script>` and tricks a victim into clicking it causes the server to **reflect** the payload back into the response body. The browser parses the response, encounters live markup where text was expected, and executes the script in the application's origin — leaking the victim's session cookie, defacing the page, or performing actions on the victim's behalf. The payload never persists; it lives only in the URL and fires only when a victim is induced to load the crafted link. This is therefore a **reflected** XSS, distinct from VULN-2 (the stored XSS in the dashboard, which has already been closed).

A secondary sink exists alongside the primary one: each result row is rendered as `<li>{row[0]} ({row[1]})</li>`, where `row[0]` is `users.username` and `row[1]` is `users.email`. Because the signup form accepts both values without sanitization, an attacker can also store a payload in either column and have it fire when *any* user runs a search that matches the attacker's row. That sink is in scope for this fix — the result-list rendering is part of the same handler — but its primary classification remains *reflected* XSS in intent, since the attacker controls the search URL that triggers the render. (The stored-XSS dashboard sink at `/welcome` is separately closed by VULN-2.)

This fix replaces every interpolation of attacker-controllable text in `search_user` with an **HTML-escaped** substitution using Python's standard-library `html.escape(value, quote=True)`. After the fix the search page renders payloads as literal text — `&lt;script&gt;alert(1)&lt;/script&gt;` — and no script executes. The fix is **surgical** and closes the **Reflected XSS** vulnerability **only**. The other intentional vulnerabilities (VULN-7 No Rate Limit, VULN-8 No CSRF) remain exploitable for educational use, and every previously-closed fix (bcrypt password hashing, parameterized SQL, removed `/download/db` route, env-sourced session secret, escaped dashboard username) remains permanently in place.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- Use the existing top-level `import html` already present in `backend/app/api/routes/auth.py` (added by the VULN-2 fix). No new import is added; the `html` module is reused.
- In the `search_user` handler:
  - Escape the reflected `q` value with `html.escape(q, quote=True)` before splicing it into the `<h3>Search results for: …</h3>` heading.
  - Escape each result-row column with `html.escape(row[i], quote=True)` before splicing it into the `<li>…</li>` items.
  - Escape the exception text with `html.escape(str(e), quote=True)` before splicing it into the `<h3>Error: …</h3>` response. The exception text is shaped by attacker-controllable inputs and must not provide a third reflection sink.
- Preserve every other line of `auth.py` byte-for-byte — including the escaped `{{username}}` substitution in `welcome_page` (preserves the closed VULN-2 fix) and the unchanged signup/login/logout/index handlers.
- Preserve `frontend/templates/dashboard.html`, `login.html`, `signup.html`, and every static asset byte-for-byte.

### 2.2 Out of Scope (Intentionally Unfixed)

This fix addresses only the Reflected XSS vulnerability. The following intentional vulnerabilities remain in place after this change and MUST NOT be remediated here:

| Vulnerability | OWASP | Status under this fix |
|---------------|-------|-----------------------|
| SQL Injection (`auth_service.py` / `auth.py` queries) | A03:2021 | Already CLOSED (parameterized) — stays closed |
| Stored XSS (`{{username}}` substitution in dashboard) | A03:2021 | Already CLOSED (`html.escape`) — stays closed |
| **Reflected XSS (`/search?q=` reflection)** | **A03:2021** | **CLOSED by this spec** |
| Session Hijacking (hardcoded session secret) | A07:2021 | Already CLOSED (env-sourced secret) — stays closed |
| Weak Password Storage | A02:2021 | Already CLOSED (bcrypt) — stays closed |
| Exposed Database endpoint (`/download/db`) | A01:2021 | Already CLOSED (route removed) — stays closed |
| No Rate Limiting | A07:2021 | Intentionally unchanged |
| CSRF (no tokens) | A01:2021 | Intentionally unchanged |

### 2.3 Explicit Preservation Note

All other intentional vulnerabilities MUST remain unchanged:

- **VULN-7 (No Rate Limiting):** no throttling middleware, per-IP counter, or `time.sleep` is added.
- **VULN-8 (No CSRF):** no CSRF token field is added to any form; no CSRF middleware is registered.

The five already-closed fixes also MUST remain closed:

- **VULN-1 (SQL Injection):** `auth_service.py` and `/search` MUST keep their parameterized `?` queries. In particular, the `/search` query MUST remain `SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?` with bound parameters; no change to the SQL string or its bindings is permitted under this fix.
- **VULN-2 (Stored XSS):** `welcome_page` MUST keep escaping the `{{username}}` substitution with `html.escape(..., quote=True)`.
- **VULN-4 (Session Hijacking):** `main.py` MUST keep sourcing `SECRET_KEY` from the environment with the `secrets.token_hex(32)` fallback.
- **VULN-5 (Weak Password Storage):** `core/security.py` MUST keep its bcrypt implementation (rounds ≥ 12) and the defensive `try/except` in `verify_password`.
- **VULN-6 (Exposed Database):** the `/download/db` route MUST NOT be re-introduced.

---

## 3. Affected Files

The fix MUST touch only the following file (plus the two specification documents). No other repository file may be created or modified.

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/api/routes/auth.py` | Modified | Escape `q`, each result-row column, and exception text before splicing them into `/search` responses |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` (env-sourced session secret — VULN-4 stays closed).
- `backend/app/services/auth_service.py` (parameterized queries + bcrypt verify — VULN-1 / VULN-5 stay closed).
- `backend/app/core/security.py` (bcrypt — VULN-5 stays closed).
- `backend/app/db/session.py` (schema and connection layer — untouched).
- `frontend/templates/dashboard.html` (the `{{username}}` placeholder and its surrounding `<strong>` element MUST remain unchanged).
- `frontend/templates/login.html`, `frontend/templates/signup.html` (no template-side change).
- Any CSS under `frontend/static/`.
- `CLAUDE.md`, `README.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md` and every other prior spec.
- `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` (no dependency change — `html` is stdlib and is already imported).

---

## 4. Functional Requirements

### FR-01: Escape the Reflected Query

- The `search_user` handler MUST run the raw `q` value through `html.escape(q, quote=True)` **before** splicing it into the `<h3>Search results for: …</h3>` response.
- The escape MUST be applied to the value used in the response, not to the value used in the SQL `LIKE` binding. The two values are decoupled: the SQL layer continues to receive the raw `q` wrapped as `f"%{q}%"` and bound as a positional `?` parameter (preserves VULN-1 closure); the HTML layer receives the escaped form.

### FR-02: Escape Each Result-Row Column

- For each row returned by the `SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?` query, the handler MUST escape both `row[0]` (the username) and `row[1]` (the email) with `html.escape(..., quote=True)` before splicing them into the `<li>…</li>` markup.
- The literal `<li>` / `</li>` / `(` / `)` wrappers around the escaped values are part of the static template and are not escaped (they are not attacker-controlled).

### FR-03: Escape the Exception Branch

- The `except` branch of `search_user` MUST run `str(e)` through `html.escape(..., quote=True)` before splicing it into the `<h3>Error: …</h3>` response.
- Rationale: exception text can incorporate attacker-controllable values (for instance, exception messages from the underlying SQLite driver can echo back fragments of the bound parameter or the raw column data). Escaping the exception text closes that sink without changing which exceptions are caught or what HTTP status is returned.

### FR-04: Quote-Aware Escaping

- Every `html.escape` call inside `search_user` MUST pass `quote=True` (the standard-library default).
- This guarantees that `<`, `>`, `&`, `"`, and `'` are all converted to their HTML entity equivalents (`&lt;`, `&gt;`, `&amp;`, `&quot;`, `&#x27;`), so a payload that escapes a quoted attribute context (e.g. `" onmouseover=alert(1) x="`) cannot break out even if a future maintainer moves the reflected value into an attribute.

### FR-05: SQL Binding Untouched

- The SQL query string MUST remain exactly `SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?`.
- The two `?` bindings MUST continue to receive `f"%{q}%"` (the raw, un-escaped `q` wrapped with SQL wildcards). Escaping `q` for HTML must not bleed into the SQL parameter — the SQL layer is a separate sink with its own (already correct, already parameterized) defense.

### FR-06: No-Op for Empty Query

- The early-return branch `if not q: return HTMLResponse(content="<h3>No search query provided</h3>")` MUST remain byte-for-byte identical. The string is a static literal with no attacker input, so no escape call is required.

### FR-07: Standard-Library Only

- The fix MUST use only the Python standard library (`html`). No third-party dependency (Jinja2, MarkupSafe, `bleach`, etc.) is added. No new import is needed; `import html` is already present at the top of `auth.py` (added by the VULN-2 fix) and MUST be reused.

### FR-08: Other Routes Unchanged

- The `index`, `signup_page`, `signup_post`, `login_page`, `login_post`, `welcome_page`, and `logout` handlers MUST remain byte-for-byte identical except where touching them is unavoidable to leave the `welcome_page` handler's existing `html.escape` call in place.
- In particular, the `welcome_page` handler MUST continue to call `html.escape(username, quote=True)` before substituting `{{username}}` (preserves the closed VULN-2 fix).

### FR-09: Response Shape Preserved

- The `/search` handler MUST continue to:
  - Return `HTMLResponse(content="<h3>No search query provided</h3>")` when `q` is empty or missing.
  - Return `HTMLResponse(content=<heading + list>)` for a successful query.
  - Return `HTMLResponse(content=<error heading>)` from the `except` branch.
- The HTTP status (default `200`), content type (`text/html`), and the surrounding HTML structure (`<h3>` heading + `<ul><li>…</li></ul>` list, or single `<h3>` error line) are unchanged; only the rendered text of attacker-controlled fragments changes (from raw to entity-encoded).

### FR-10: Connection Lifecycle Preserved

- The `try` / `except` / `finally` structure of `search_user` MUST be preserved. The `conn = get_db()` call, the `cursor = conn.execute(...)` call, the `cursor.fetchall()` call, and the `conn.close()` call in the `finally` block MUST remain in place. The fix only changes the strings written into `HTMLResponse(content=…)`; it does not refactor the database access pattern.

---

## 5. Non-Functional Requirements

### NFR-01: XSS Immunity at the `/search` Sinks

- After the fix, no value supplied through the `q` query parameter — and no value stored in `users.username` or `users.email` — can introduce executable script, event handler, or live HTML markup into the rendered `/search` response.
- Specifically, the payloads `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, `"><script>alert(1)</script>`, `<svg/onload=alert(1)>`, and `javascript:alert(1)` MUST all render as inert visible text in the heading, the list items, and the error response alike.

### NFR-02: Surgical Scope

- Exactly one vulnerability (Reflected XSS) is closed. The diff MUST NOT touch session secrets, the SQL construction, the dashboard's `{{username}}` escaping, rate-limiting posture, CSRF posture, or the bcrypt verification.

### NFR-03: API Stability

- The public route signature `GET /search` is unchanged: same path, same method, same `q` query parameter with the same `str` type and `""` default, same `HTMLResponse` return type.
- No new query parameters, headers, or session keys are introduced. No redirect is added; the behavior for the empty-`q` case is unchanged.

### NFR-04: No Behavioral Regression for Benign Queries

- A query consisting only of printable ASCII letters, digits, underscores, hyphens, or spaces MUST render verbatim in the heading and in each result-list row. `html.escape` is a no-op on such characters.

### NFR-05: No Information Leakage

- The fix MUST NOT change any HTTP status code, log line, or response timing on `/search` or any other route. Output encoding is a pure-CPU transformation with no observable side channel.
- The set of exceptions caught by the `except Exception as e` clause is unchanged; only the rendering of `str(e)` is escaped. No exception is swallowed that was previously surfaced, and none is surfaced that was previously swallowed.

### NFR-06: Standard-Library Only / Zero Dependency Delta

- No entry is added to `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock`. The `html` module is part of CPython's standard library and is already imported.

### NFR-07: Encoding Robustness

- The fix MUST correctly escape Unicode queries and Unicode column values. `html.escape` operates on `str` and preserves non-ASCII code points verbatim (it transforms only the five special characters listed in FR-04); a query like `日本語` continues to render as `日本語` in the heading, while `日本語<script>` renders as `日本語&lt;script&gt;`.

### NFR-08: SQL-Layer Defense Preserved

- The SQL layer's parameterized-`?` defense (VULN-1 closure) MUST remain the sole defense at the SQL boundary. Escaping `q` for HTML MUST NOT be applied to the value bound into the `LIKE` clause; the two defenses operate on different sinks and MUST NOT be conflated.

---

## 6. Success Paths

### SP-01: Benign Query Renders Unchanged

1. User requests `GET /search?q=alice`.
2. The handler binds `%alice%` into both `LIKE ?` placeholders, fetches matching rows, and computes `html.escape("alice", quote=True) == "alice"`.
3. The response body contains `<h3>Search results for: alice</h3>` and a `<ul>` of `<li>username (email)</li>` rows. No visual or functional regression.

### SP-02: Script-Tag Payload Reflected as Text

1. Attacker tricks the victim into loading `GET /search?q=<script>alert(1)</script>`.
2. The SQL bind receives `%<script>alert(1)</script>%`; the parameterized query returns zero rows (or any rows whose username/email matches the LIKE pattern — irrelevant to the XSS).
3. The handler computes `html.escape("<script>alert(1)</script>", quote=True) == "&lt;script&gt;alert(1)&lt;/script&gt;"`.
4. The response body contains `<h3>Search results for: &lt;script&gt;alert(1)&lt;/script&gt;</h3>` followed by `<ul></ul>` (or whatever rows match). **The browser renders the literal text `<script>alert(1)</script>` inside the heading; no alert dialog appears; no JavaScript executes.**

### SP-03: Event-Handler Payload Reflected as Text

1. Victim is induced to load `GET /search?q=<img src=x onerror=alert(1)>`.
2. The escaped substitution renders `&lt;img src=x onerror=alert(1)&gt;` inside the heading.
3. The browser parses no `<img>` tag and dispatches no `onerror` handler. **No alert fires.**

### SP-04: Attribute-Breakout Payload Neutralized

1. Victim is induced to load `GET /search?q=" onmouseover=alert(1) x="`.
2. The escaped substitution renders `&quot; onmouseover=alert(1) x=&quot;` inside the heading.
3. Even if a future maintainer accidentally moves the heading into an HTML attribute, the `quote=True` setting from FR-04 prevents the attacker from closing the attribute.

### SP-05: Result-Row Payload Rendered Inert

1. An account exists whose `username` column is `<script>alert(1)</script>` (registered before any fix, or registered under the current schema, which deliberately does not sanitize input).
2. A separate victim is induced to load `GET /search?q=script` (or any query that matches the malicious row).
3. The handler escapes `row[0]` to `&lt;script&gt;alert(1)&lt;/script&gt;` before splicing it into `<li>…</li>`.
4. The list renders the payload as inert text. **No alert fires** even though the underlying database row is still malicious.

### SP-06: Empty Query Returns Static Notice

1. User requests `GET /search` or `GET /search?q=`.
2. The handler returns the static `<h3>No search query provided</h3>` body. No SQL is executed, no escape function is invoked, no change from the pre-fix behavior.

### SP-07: Unicode Query Round-Trip

1. User requests `GET /search?q=日本語`.
2. `html.escape("日本語", quote=True)` returns `"日本語"` unchanged.
3. The response contains `<h3>Search results for: 日本語</h3>` and whatever rows match.

---

## 7. Edge Cases

### EC-01: Pre-Existing Malicious Row

- The database file pre-dates this fix and contains a row whose `username` or `email` column is `<script>alert(1)</script>` (registered before the fix shipped).
- A search whose `LIKE` pattern matches that row returns the malicious row from SQL.
- The escaped list rendering produces `&lt;script&gt;alert(1)&lt;/script&gt;` inside `<li>…</li>` — **no script executes**, even though the underlying data is still malicious. **No database migration is required.**

### EC-02: Empty Query Parameter

- `GET /search?q=` (with `q` present but empty) returns `<h3>No search query provided</h3>` via the existing `if not q:` short-circuit. No escape call is invoked; behavior is identical to the pre-fix implementation.

### EC-03: Missing Query Parameter

- `GET /search` (with `q` absent from the URL) defaults to `q = ""` via the `q: str = ""` signature, then takes the same short-circuit as EC-02.

### EC-04: Query Containing Only `&`

- A query of `&` is rendered as `&amp;` in the heading. The browser displays a single `&` character, identical to the visual rendering before the fix on a single-character benign string — but the entity form is mandatory because `html.escape` always transforms `&` first.

### EC-05: Database Error Surfacing in the `except` Branch

- A SQLite driver error whose message includes an attacker-supplied fragment (for instance, an integrity error echoing back part of the bound parameter) is caught by `except Exception as e`.
- The handler computes `html.escape(str(e), quote=True)` and splices the escaped form into `<h3>Error: …</h3>`. The attacker fragment, if any, renders as inert text. **No XSS sink remains in the error path.**

### EC-06: Connection Cleanup on the Escaped Path

- The `finally: conn.close()` block runs unchanged on both the success and the error paths. Escaping is a pure-Python transformation on already-fetched strings; it does not interact with the connection lifecycle.

### EC-07: Multi-Row Result

- A query that matches multiple rows produces multiple `<li>…</li>` items. Each row is escaped independently; one malicious row does not affect the rendering of the others.

### EC-08: Query With Embedded Newlines

- A query containing `\n` or `\r` is left intact by `html.escape` (whitespace is not in the escape set). The browser collapses the whitespace per normal HTML rules. No script execution path is opened.

### EC-09: Very Long Query

- A 10,000-character query is escaped in a single `html.escape` call (O(n) in the length of the string) and substituted into the heading. There is no length cap and no performance regression observable at human-perceivable scales.

### EC-10: Query Matches the Dashboard's Already-Escaped Username

- A username stored as `<script>alert(1)</script>` renders as inert text on the dashboard (closed by VULN-2 fix) AND as inert text in the search list (closed by this fix). The two fixes are independent — neither one shadows the other; both must remain in place.

---

## 8. Acceptance Criteria

### AC-01: `html` Module Still Imported

- `backend/app/api/routes/auth.py` continues to contain the top-level `import html` statement added by the VULN-2 fix. The fix does NOT remove or duplicate this import.

### AC-02: Reflected `q` Escaped Before Splicing

- The `search_user` handler passes `q` through `html.escape(..., quote=True)` before the value reaches the `<h3>Search results for: …</h3>` interpolation.

### AC-03: Result Rows Escaped Before Splicing

- The `search_user` handler passes each of `row[0]` and `row[1]` through `html.escape(..., quote=True)` before the values reach the `<li>…</li>` interpolation.

### AC-04: Exception Text Escaped Before Splicing

- The `except` branch in `search_user` passes `str(e)` through `html.escape(..., quote=True)` before the value reaches the `<h3>Error: …</h3>` interpolation.

### AC-05: SQL Query Unchanged

- The SQL string remains exactly `SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?` and the bound parameters remain `[f"%{q}%", f"%{q}%"]` using the **raw** (un-escaped) `q`. `grep -n 'LIKE ?' backend/app/api/routes/auth.py` matches; no concatenation of `q` into the SQL string is introduced.

### AC-06: Quote-Aware Escaping in Use

- Every `html.escape` call inside `search_user` passes `quote=True` (or relies on the standard-library default, which is `True`). A query of `" onmouseover=alert(1) x="` is rendered with `&quot;` entities in place of every double quote.

### AC-07: `<script>` Query Reflected as Text

- `GET /search?q=<script>alert(1)</script>` returns a response body containing the literal substring `&lt;script&gt;alert(1)&lt;/script&gt;` and **not** the live `<script>alert(1)</script>` form inside the heading.

### AC-08: `<img onerror>` Query Reflected as Text

- `GET /search?q=<img src=x onerror=alert(1)>` returns a response body containing `&lt;img src=x onerror=alert(1)&gt;` and **not** the live `<img>` tag with `onerror` inside the heading.

### AC-09: Benign Queries Unchanged

- `GET /search?q=alice` returns a response body whose heading is exactly `<h3>Search results for: alice</h3>` — no entity encoding, no visual difference from the pre-fix response.

### AC-10: Empty-Query Short-Circuit Unchanged

- `GET /search` and `GET /search?q=` each return a response body exactly equal to `<h3>No search query provided</h3>` (byte-for-byte unchanged).

### AC-11: Dashboard Escaping Preserved (VULN-2)

- `welcome_page` still calls `html.escape(username, quote=True)` before substituting `{{username}}`. Registering a user with `username=<script>alert(1)</script>`, logging in, and requesting `/welcome` returns a body containing `&lt;script&gt;alert(1)&lt;/script&gt;` (not the live form).

### AC-12: Other Vulnerabilities Preserved

- VULN-1 (SQL Injection): `auth_service.py` and `/search` still use parameterized queries (already closed, remains closed).
- VULN-4 (Session Hijacking): `main.py` still sources `SECRET_KEY` from the environment with the `secrets.token_hex(32)` fallback (already closed, remains closed).
- VULN-5 (Weak Password): `core/security.py` still uses bcrypt with rounds ≥ 12 (already closed, remains closed).
- VULN-6 (Exposed DB): `GET /download/db` still returns HTTP 404 (already closed, remains closed).
- VULN-7 (No Rate Limit): no throttling middleware was added.
- VULN-8 (No CSRF): no CSRF token field was added to the login or signup form; no CSRF middleware was registered.

### AC-13: Stored Data Untouched

- The database columns `users.username` and `users.email` continue to store the raw, unsanitized values for any account registered with a malicious payload. The fix is purely at the output sink.

### AC-14: Only `auth.py` Modified

- `git status --porcelain` shows `backend/app/api/routes/auth.py` as the only modified source file, plus the new file `.claude/specs/reflected-xss-fix.md` (and, once a plan is authored, `.claude/specs/reflected-xss-fix-plan.md`). No other path.

### AC-15: Application Boots

- The app starts via `uv run backend/app/main.py` with no `ImportError`, `NameError`, or traceback.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | `html` module still imported | Repo checkout | `grep -n '^import html$' backend/app/api/routes/auth.py` matches a line |
| TC-02 | `search_user` uses `html.escape` on `q` | Repo checkout | `grep -n 'html.escape(' backend/app/api/routes/auth.py` matches a line inside `search_user` operating on `q` |
| TC-03 | `search_user` escapes each row column | Repo checkout | Inspection of `search_user` shows `row[0]` and `row[1]` escaped before splicing |
| TC-04 | `search_user` escapes the exception branch | Repo checkout | Inspection of `search_user` shows `str(e)` escaped before splicing |
| TC-05 | Benign query renders unchanged | App running | `GET /search?q=alice` body contains `<h3>Search results for: alice</h3>` |
| TC-06 | `<script>` query rendered inert | App running | `GET /search?q=<script>alert(1)</script>` body contains `&lt;script&gt;alert(1)&lt;/script&gt;` and **not** the live form |
| TC-07 | `<img onerror>` query rendered inert | App running | `GET /search?q=<img src=x onerror=alert(1)>` body contains `&lt;img src=x onerror=alert(1)&gt;` |
| TC-08 | Attribute-breakout query escaped | App running | `GET /search?q=" onmouseover=alert(1) x="` body contains `&quot;` entities; no live attribute injection |
| TC-09 | SVG payload rendered inert | App running | `GET /search?q=<svg/onload=alert(1)>` body contains `&lt;svg/onload=alert(1)&gt;` |
| TC-10 | Stored malicious row rendered inert in results | User registered with `username=<script>alert(1)</script>` | `GET /search?q=script` body contains `&lt;script&gt;alert(1)&lt;/script&gt;` inside an `<li>` and **not** the live form |
| TC-11 | Empty query short-circuit unchanged | App running | `GET /search` and `GET /search?q=` each return exactly `<h3>No search query provided</h3>` |
| TC-12 | Unicode query works | App running | `GET /search?q=日本語` body contains `<h3>Search results for: 日本語</h3>` |
| TC-13 | Dashboard escaping preserved (VULN-2) | User registered with `username=<script>alert(1)</script>` | `/welcome` body contains `&lt;script&gt;alert(1)&lt;/script&gt;` (output-encoding fix unchanged) |
| TC-14 | SQL injection stays closed (VULN-1) | Repo checkout | `grep -n 'WHERE username = ?' backend/app/services/auth_service.py` matches; `grep -n 'LIKE ?' backend/app/api/routes/auth.py` matches |
| TC-15 | Session secret stays env-sourced (VULN-4) | Repo checkout | `grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py` matches; `grep 'super-secret-key-12345' backend/app/main.py` returns no matches |
| TC-16 | Bcrypt stays in use (VULN-5) | Repo checkout | `grep -n 'bcrypt' backend/app/core/security.py` matches |
| TC-17 | `/download/db` stays removed (VULN-6) | App running | `GET /download/db` → HTTP 404 |
| TC-18 | No rate limiting added (VULN-7) | App running | 50 sequential `POST /login` calls all return HTTP 401, never 429 |
| TC-19 | No CSRF tokens added (VULN-8) | App running | `curl /login` and `curl /signup` HTML contain no `csrf_token` field |
| TC-20 | Affected-files audit | After change | `git status --porcelain` shows only `auth.py` modified plus the new spec doc |
| TC-21 | Application boots cleanly | Fresh checkout | `uv run backend/app/main.py` starts with no traceback |
| TC-22 | Stored data unchanged | User registered with `<script>` username | `sqlite3 vulnerable_app.db "SELECT username FROM users WHERE ...";` still returns the raw `<script>` payload (output-encoding fix, not input filtering) |

---

## 10. Verification Steps

Run from the repository root.

### 10.1 Confirm the Import is Present and Singular (AC-01, TC-01)

```bash
grep -cn '^import html$' backend/app/api/routes/auth.py
```

Expected: `1` (a single matching line near the top of the file; not removed, not duplicated).

### 10.2 Confirm Escape on the Reflected `q`, on the Row Columns, and on the Exception (AC-02–AC-04, TC-02–TC-04)

```bash
grep -n 'html.escape(' backend/app/api/routes/auth.py
```

Expected: at least four matching lines — one already inside `welcome_page` (escaping `username`, from VULN-2) and three new ones inside `search_user` (escaping `q`, escaping each row column, escaping `str(e)`). Manual inspection confirms the escaped values are what reach the `f"…{…}…"` interpolations and that no raw `q`, raw `row[0]`/`row[1]`, or raw `str(e)` remains in any `HTMLResponse(content=…)` call.

### 10.3 Start the Application (AC-15, TC-21)

```bash
uv run backend/app/main.py
```

The server listens on `http://localhost:3001` with no import/boot error.

### 10.4 Benign Query Round-Trip (AC-09, TC-05)

```bash
curl -s 'http://localhost:3001/search?q=alice' | grep -o '<h3>Search results for: alice</h3>'
```

Expected: the literal heading is printed.

### 10.5 `<script>` Payload Reflected Inert (AC-07, TC-06)

```bash
BODY=$(curl -s 'http://localhost:3001/search?q=<script>alert(1)</script>')
echo "$BODY" | grep -o '&lt;script&gt;alert(1)&lt;/script&gt;' && echo 'escaped: OK'
echo "$BODY" | grep -c '<h3>Search results for: <script>alert(1)</script></h3>'
```

Expected: the escaped substring is found (prints `escaped: OK`); the live-`<script>` form inside the heading is **not** found (count is `0`).

### 10.6 `<img onerror>` Payload Reflected Inert (AC-08, TC-07)

```bash
curl -s 'http://localhost:3001/search?q=<img src=x onerror=alert(1)>' \
  | grep -o '&lt;img src=x onerror=alert(1)&gt;'
```

Expected: the escaped substring is printed.

### 10.7 Attribute-Breakout Payload Neutralized (AC-06, TC-08)

```bash
curl -s 'http://localhost:3001/search?q=%22%20onmouseover=alert(1)%20x=%22' | grep -o '&quot;'
```

Expected: the `&quot;` entity is printed (confirms quote-aware escaping).

### 10.8 Result-Row Payload Reflected Inert (SP-05, TC-10)

```bash
curl -s -c xss_jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=<script>alert(1)</script>' \
     --data-urlencode 'email=xss@x' \
     --data-urlencode 'password=p'
curl -s 'http://localhost:3001/search?q=script' | grep -o '<li>&lt;script&gt;alert(1)&lt;/script&gt;'
```

Expected: a list item containing the escaped form is printed; no live `<script>` tag is rendered inside any `<li>`.

### 10.9 Empty-Query Short-Circuit Unchanged (AC-10, TC-11)

```bash
curl -s 'http://localhost:3001/search'    | diff - <(printf '%s' '<h3>No search query provided</h3>')
curl -s 'http://localhost:3001/search?q=' | diff - <(printf '%s' '<h3>No search query provided</h3>')
```

Expected: both `diff` invocations produce no output (byte-for-byte match).

### 10.10 Stored Data Still Malicious (AC-13, TC-22)

```bash
sqlite3 vulnerable_app.db "SELECT username FROM users WHERE username LIKE '<script>%';"
```

Expected: returns the raw `<script>alert(1)</script>` string — confirming the fix is output encoding, not input filtering.

### 10.11 Dashboard Escaping Preserved (AC-11, TC-13)

```bash
# Using the same session jar from §10.8 (xss_jar.txt)
curl -s -c xss_jar.txt -b xss_jar.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=<script>alert(1)</script>' \
     --data-urlencode 'password=p'
curl -s -b xss_jar.txt http://localhost:3001/welcome | grep -o '&lt;script&gt;alert(1)&lt;/script&gt;'
```

Expected: the escaped substring is printed (VULN-2 closure intact).

### 10.12 Vulnerability Preservation Walkthrough (AC-12, TC-14–TC-19)

```bash
# VULN-1 SQL injection stays closed (TC-14)
grep -n 'WHERE username = ?' backend/app/services/auth_service.py
grep -n 'LIKE ?' backend/app/api/routes/auth.py

# VULN-4 Session secret env-sourced (TC-15)
grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py
grep -n 'super-secret-key-12345' backend/app/main.py || echo '(hardcoded secret absent — preserved)'

# VULN-5 Bcrypt stays in use (TC-16)
grep -n 'bcrypt' backend/app/core/security.py

# VULN-6 /download/db stays removed (TC-17)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/download/db
# Expected: 404.

# VULN-7 No rate limiting (TC-18)
for i in {1..50}; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
       --data-urlencode 'username=ghost' --data-urlencode "password=$i"
done | sort -u
# Expected: only 401 in the deduplicated output.

# VULN-8 No CSRF tokens (TC-19)
curl -s http://localhost:3001/login  | grep -i csrf || echo '(no csrf field — preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo '(no csrf field — preserved)'
```

### 10.13 Affected-Files Audit (AC-14, TC-20)

```bash
git status --porcelain
```

Expected output — exactly one modified source file plus the new spec doc (and, if a plan has been authored alongside, the plan doc):

```
 M backend/app/api/routes/auth.py
?? .claude/specs/reflected-xss-fix.md
```

(If `.claude/specs/reflected-xss-fix-plan.md` is also present, it appears as an additional `??` line. No other path is permitted.)

---

## 11. Operational Note

This fix requires **no database migration and no data changes**.

- Existing user accounts (including any whose `username` or `email` columns contain malicious markup from before any fix shipped) continue to work without modification — they can still log in, sign up, and appear in `/search` result lists.
- The `vulnerable_app.db` file is not modified, moved, or deleted.
- The `users` table schema is unchanged.
- The session cookie format is unchanged.

After deploying this change:

- The search page at `/search` renders every reflected query — and every result-row column, and every error message — as inert text. A crafted link of the form `http://localhost:3001/search?q=<script>…</script>` no longer executes script in the victim's browser.
- The educational demonstration of the underlying issue is preserved: students can still inspect the raw `q` they typed in the URL bar, then compare it to the safely-rendered heading in the response to understand that the correct mitigation lives at the **output sink**, not at the input boundary.
- Combined with the VULN-2 fix, both XSS vulnerabilities in the original challenge set are now closed at their respective output sinks while every other intentional vulnerability (VULN-7 No Rate Limit, VULN-8 No CSRF) remains exploitable for further exercises.
