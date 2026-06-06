# Software Specification Document (Implementation Addendum)

**Version:** 1.0.0
**Last Updated:** June 6, 2026
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)

---

## 1. Scope

This document captures **implementation-level behavior** required to reproduce the Vulnerable Web Application exactly. It intentionally omits:

- Product goals and educational objectives (see PRD.md)
- System architecture and technology stack (see TDD.md)
- Vulnerability descriptions and exploitation guides (see PRD.md §3.2, TDD.md §4)
- Database schema definitions (see TDD.md §11.3)
- Endpoint inventories (see TDD.md §11.4)

Everything in this document describes **how the application behaves at runtime** — the observable contracts that a compatible implementation must satisfy.

---

## 2. Runtime Behavior

### 2.1 Database Initialization

- On application startup, `init_db()` is called to execute `CREATE TABLE IF NOT EXISTS` for the `users` table.
- If the database file (`vulnerable_app.db`) is missing, SQLite creates it automatically on first connection.
- If the database file exists but the table is missing, the table is recreated without affecting other data.
- Data persists across application restarts — the database file is never deleted or truncated by the application.

### 2.2 Static Asset Serving

- Static files (CSS, images) are mounted via FastAPI's `StaticFiles` and available immediately after application boot.
- CSS served from `/static/css/` path, images from `/static/images/` path.

### 2.3 Template Loading

- HTML templates (`login.html`, `signup.html`, `dashboard.html`) are loaded from disk on **every request**.
- No template caching mechanism exists — file modifications are reflected on the next request without restart.
- Templates are read as raw strings using Python file I/O.

### 2.4 Dashboard Content Injection

- The dashboard template contains the placeholder `{{username}}`.
- Before serving the response, the server performs `html.replace('{{username}}', username)` using the username from the session.
- This is a **runtime string substitution**, not a template engine — no escaping is applied (intentional vulnerability).

### 2.5 Authentication State

- Authentication is determined **solely** by the presence of `user_id` in the session dictionary.
- No token expiration, no role checks, no secondary validation.
- If `session['user_id']` exists, the user is considered authenticated.

---

## 3. User Flows

### 3.1 Registration Flow

1. User navigates to `/signup` → server reads `signup.html` from disk and returns it.
2. User fills in username, email, password, and confirm password fields.
3. **Client-side validation**: JavaScript checks that password and confirm password match before submission. If mismatch, red error text appears below the confirm password field — no page reload, no server request.
4. Form submits via standard HTML POST to `/signup`.
5. Server receives form data via FastAPI `Form()` parameters.
6. `auth_service.signup()` hashes the password with MD5, constructs an INSERT query via string concatenation, and executes it.
7. On success: server returns a `RedirectResponse` to `/login`.
8. On failure (duplicate username): server returns an `HTMLResponse` with an error message.

### 3.2 Login Flow

1. User navigates to `/login` → server reads `login.html` from disk and returns it.
2. User fills in username and password fields.
3. **Client-side submission**: JavaScript intercepts form submission and sends an **async `fetch()` POST request** to `/login`.
4. Server receives form data, calls `auth_service.login()`.
5. Password is hashed with MD5, SQL SELECT query is built via string concatenation, and executed.
6. On success: server sets `session['user_id']`, `session['username']`, `session['email']`, and returns a **JSON response** with redirect URL.
7. Client-side JavaScript reads the JSON response and performs `window.location.href` redirect to `/welcome`.
8. On failure: server returns a **JSON response** with an error message. Client-side JavaScript displays the error inline without page reload.

### 3.3 Dashboard Flow

1. User requests `GET /welcome`.
2. Server checks for `user_id` in `request.session`.
3. If missing: `RedirectResponse` to `/login`.
4. If present: server reads `dashboard.html` from disk.
5. Server performs `html.replace('{{username}}', session['username'])`.
6. Server returns the modified HTML as an `HTMLResponse`.

### 3.4 Logout Flow

1. User clicks the logout button on the dashboard.
2. Browser sends `GET /logout`.
3. Server clears all session data (`request.session.clear()`).
4. Server returns `RedirectResponse` to `/login`.
5. Subsequent requests to `/welcome` redirect to `/login` (session no longer contains `user_id`).

---

## 4. Functional Requirements

### FR-01: Session Management

- Sessions are managed by Starlette `SessionMiddleware` with a hardcoded secret key `"super-secret-key-12345"`.
- Session data is stored in a signed cookie on the client side.
- Three values are stored on login: `user_id` (integer), `username` (string), `email` (string).
- `session.clear()` removes all session data on logout.
- No session expiration is configured.

### FR-02: Dynamic User Context

- The dashboard template uses the `{{username}}` placeholder.
- The server substitutes this placeholder with the session's `username` value at request time.
- No HTML escaping is applied to the substituted value (enables Stored XSS).

### FR-03: Route Protection

- Only `/welcome` is protected by session authentication.
- Protection logic: check `request.session.get('user_id')` — if falsy, redirect to `/login`.
- All other routes (including `/download/db` and `/search`) have no authentication requirement.

### FR-04: Error Handling

- **Registration errors**: Duplicate username returns an HTML error page. Missing required fields are not explicitly validated server-side beyond non-null checks.
- **Login errors**: Invalid credentials return a JSON response with error details. Client-side JavaScript renders the error message inline.
- **General errors**: No global error handler. Unhandled exceptions surface FastAPI's default error responses.

### FR-05: Search Processing

- `GET /search?q=<query>` accepts a query parameter.
- The query is used in a SQL SELECT matching against `username` and `email` columns.
- Results are constructed as an HTML string with `<li>` elements.
- The query value is reflected directly in the HTML response without escaping (enables Reflected XSS).
- If no query parameter is provided, an appropriate response is returned.

### FR-06: Persistence

- SQLite database file (`vulnerable_app.db`) is stored at the project root.
- Database connection uses `check_same_thread=False` and `Row` factory.
- No connection pooling — each database operation opens a fresh connection via `get_db()`.
- The `users` table has a `UNIQUE` constraint on `username`, enforced at the database level.

---

## 5. Complete Visual Design Specification

### 5.1 Global Design System

#### Typography

- **Font Stack**: `'Segoe UI', system-ui, -apple-system, sans-serif`

| Element | Size | Weight |
|---------|------|--------|
| Main titles | 2rem | 800 |
| Section titles | 1.4rem | 700 |
| Form titles | 1.7rem | 700 |
| Card titles | 0.95rem | 700 |
| Body text | 0.9rem | 400 |
| Labels | 0.82rem | 600 |
| Buttons | 1rem | 600 |

#### Primary Colors

| Swatch | Hex | Usage |
|--------|-----|-------|
| Deep Indigo | `#1a237e` | Primary brand, headers, buttons, hero gradients |
| Medium Indigo | `#3949ab` | Focus states, gradient endpoints, accents |
| Dark Indigo | `#283593` | Gradient midpoints, darker accents |
| Near Black | `#0f172a` | Deep text, overlay backgrounds |
| Light Gray-Blue | `#eef1f8` | Dashboard body background |
| White | `#ffffff` | Form panels, cards, header background |

#### Text Colors

| Hex | Usage |
|-----|-------|
| `#1e293b` | Primary body text |
| `#475569` | Secondary text, descriptions |
| `#64748b` | Muted text, placeholders |
| `#c5cae9` | Light text on dark backgrounds, input borders |
| `#1a237e` | Link text, emphasis text on light backgrounds |

#### Border Radius

| Element | Radius |
|---------|--------|
| Inputs | 8px |
| Buttons | 8px |
| Cards | 10–12px |
| Status tags | 6px |

#### Shadows

| Context | Value |
|---------|-------|
| Header | `0 2px 10px rgba(26, 35, 126, 0.08)` |
| Card hover | `0 4px 16px rgba(26, 35, 126, 0.10)` |
| Focus glow | `0 0 0 3px rgba(57, 73, 171, 0.12)` |

### 5.2 Shared Header

- **Position**: Fixed to viewport top.
- **Height**: 70px.
- **Background**: White (`#ffffff`).
- **Bottom border**: Subtle light border.
- **Shadow**: `0 2px 10px rgba(26, 35, 126, 0.08)`.
- **Left content**: Application title text.
- **Right content**: Three organizational logos (PUCIT, Excaliat, FCCU) displayed at 54×54px each.
- Present on all pages (login, signup, dashboard).

### 5.3 Login Page

**Layout**: Two-column 50/50 split-screen.

**Left Panel (Decorative)**:
- Background: Linear gradient from `#0d1b5e` → `#1a237e` → `#283593`.
- Content (centered vertically):
  - Badge/label element (small uppercase text).
  - Welcome heading (large, white, bold).
  - Description paragraph (white, lighter weight).
  - Bullet list of features/benefits (white text).
- Decorative elements: Semi-transparent white circle overlays at ~7% opacity, positioned as background decoration.

**Right Panel (Form)**:
- Background: White.
- Form container: max-width 400px, centered horizontally and vertically.
- **Form title**: Bold heading.
- **Form subtitle**: Muted descriptive text below title.
- **Username field**: Text input with label.
- **Password field**: Password input with label.
- **Error message area**: Hidden by default. When shown: light red background (`#fef2f2`), red border, dark red text (`#991b1b`).
- **Login button**: Full-width, `#1a237e` background, white text, 8px border radius.
- **Signup link**: Text link below button directing to `/signup`.

**Input Styling**:
- Background: `#f8f9ff`.
- Border: `1.5px solid #c5cae9`.
- Border radius: 8px.
- Focus state: border changes to `#3949ab`, box-shadow `0 0 0 3px rgba(57, 73, 171, 0.12)`.

### 5.4 Signup Page

**Layout**: Identical split-screen structure to login page.

**Left Panel**: Same gradient, same decorative circles, same content structure (adapted text for registration context).

**Right Panel (Form)**:
- Same container styling as login.
- **Fields**: Username, Email, Password, Confirm Password.
- **Password mismatch validation**: When confirm password does not match password, red error text appears below the confirm password field. This is **client-side only** — no page reload, no server request.
- **Submit button**: Full-width, same styling as login button.
- **Login link**: Text link below button directing to `/login`.

### 5.5 Dashboard Page

**Body background**: `#eef1f8`.

**Hero Banner**:
- Positioned directly beneath the fixed header.
- Background: Linear gradient `#1a237e` → `#3949ab`.
- **Left section**: Title text and subtitle (white).
- **Right section**: Displays logged-in username and a semi-transparent white logout button.

**Content Area**:
- Max-width: 1100px, centered horizontally.

**Mission Card**:
- White background, rounded corners.
- Section title and descriptive paragraph about the application's purpose.

**Vulnerabilities to Discover Section**:
- Section header: Uppercase, small, bold text.
- **Card grid**: Two-column layout containing 8 vulnerability cards.
- **Each card**: White background, rounded corners (10–12px), light border, hover shadow (`0 4px 16px rgba(26, 35, 126, 0.10)`).
- **Each card contains**: A colored pill/tag indicating vulnerability type, and a description.

**Tag Color Mapping**:

| Vulnerability | Tag Color |
|---------------|-----------|
| SQL Injection | Yellow |
| XSS (Stored & Reflected) | Red |
| Session Hijacking | Purple |
| Brute Force / No Rate Limiting | Orange |
| Weak Crypto / Password Storage | Green |
| Exposed Database | Blue |
| CSRF | Pink |

**Process Steps Section**:
- Three cards displayed horizontally.
- Each card: `#1a237e` background, white text.
- Circular numbered badge (1, 2, 3).
- Step labels: **Find**, **Exploit**, **Mitigate**.

### 5.6 Responsive Behavior

- **Desktop**: Split-screen layout for auth pages; two-column card grid on dashboard; horizontal process steps.
- **Mobile**: Auth pages stack vertically (decorative panel above form). Dashboard cards become single-column. Process steps stack vertically. Header logos shrink in size.

---

## 6. Form Specifications

### 6.1 Registration Form

| Field | Type | Name | Required |
|-------|------|------|----------|
| Username | text | `username` | Yes |
| Email | email | `email` | Yes |
| Password | password | `password` | Yes |
| Confirm Password | password | `confirm_password` | Yes (client-side only) |

- **Submission method**: Standard HTML form POST to `/signup`.
- **Client-side validation**: JavaScript validates password === confirm_password before allowing submission. On mismatch, red error text appears below the confirm password field without page reload.
- **Confirm password is not sent to the server** — it is used only for client-side validation.

### 6.2 Login Form

| Field | Type | Name | Required |
|-------|------|------|----------|
| Username | text | `username` | Yes |
| Password | password | `password` | Yes |

- **Submission method**: JavaScript `fetch()` API — async POST request.
- **Request format**: Form-encoded data sent to `/login`.
- **Success response**: JSON with redirect URL. JavaScript performs `window.location.href` redirect.
- **Failure response**: JSON with error message. JavaScript displays error inline in the error message area without page reload.

---

## 7. Validation Rules

### 7.1 Registration

- Username, email, and password are required (non-empty).
- No format validation on email (accepts any non-empty string).
- No password strength requirements.
- Username uniqueness is enforced by the database `UNIQUE` constraint — not by application-level pre-checks.
- Duplicate username results in a database error, caught and returned as an HTML error response.

### 7.2 Login

- Username and password are required (non-empty).
- Credentials are validated by querying the database with the hashed password.
- No account lockout after failed attempts.

### 7.3 Search

- The `q` query parameter is required.
- No sanitization or escaping of the query value.
- Query is matched against both `username` and `email` columns.

---

## 8. Session State Model

### 8.1 Stored Values

| Key | Type | Source | Set When |
|-----|------|--------|----------|
| `user_id` | integer | `users.id` column | Successful login |
| `username` | string | `users.username` column | Successful login |
| `email` | string | `users.email` column | Successful login |

### 8.2 Lifecycle

1. **Creation**: All three values set simultaneously after successful credential verification in `auth_service.login()`.
2. **Usage**: `user_id` checked on every request to `/welcome` for access control. `username` read for dashboard template substitution.
3. **Destruction**: `request.session.clear()` called on `GET /logout`, removing all keys.

### 8.3 Storage Mechanism

- Session data is serialized into a signed cookie using Starlette's `SessionMiddleware`.
- The signing secret is `"super-secret-key-12345"` (hardcoded).
- Cookie is sent with every request; no server-side session store exists.

---

## 9. Data Lifecycle Rules

| Event | Behavior |
|-------|----------|
| **Creation** | User record created on successful registration (POST `/signup`). |
| **Read** | User record queried during login (credential check) and search (username/email match). |
| **Update** | No update workflow exists. User records are immutable after creation. |
| **Delete** | No deletion workflow exists. No account removal functionality. |
| **Recovery** | No password reset or account recovery mechanism. |

---

## 10. Success Paths

### SP-01: Successful Registration

1. User navigates to `/signup`.
2. Fills all four fields with valid data (passwords match).
3. Submits form.
4. Server creates user record.
5. Server redirects to `/login`.
6. User sees the login form.

### SP-02: Successful Login

1. User navigates to `/login`.
2. Enters valid username and password.
3. JavaScript sends async fetch POST.
4. Server validates credentials, sets session.
5. Server returns JSON with redirect URL.
6. JavaScript redirects to `/welcome`.
7. User sees the dashboard with their username.

### SP-03: Dashboard Access

1. Authenticated user requests `/welcome`.
2. Server finds `user_id` in session.
3. Server loads `dashboard.html`, substitutes `{{username}}`.
4. User sees personalized dashboard with vulnerability list.

### SP-04: Successful Logout

1. User clicks logout button on dashboard.
2. Browser sends `GET /logout`.
3. Server clears session.
4. Server redirects to `/login`.
5. User sees login form. Subsequent `/welcome` requests redirect to `/login`.

---

## 11. Alternate Paths

### AP-01: Duplicate Username Registration

1. User submits registration with an existing username.
2. Database `UNIQUE` constraint violation occurs.
3. Server catches the error.
4. Server returns an HTML response with an error message indicating the username is taken.
5. User remains on the signup page.

### AP-02: Invalid Login Credentials

1. User submits login with incorrect username or password.
2. SQL query returns no matching rows.
3. Server returns a JSON error response.
4. Client-side JavaScript displays the error message inline.
5. User remains on the login page. No page reload occurs.

### AP-03: Unauthorized Dashboard Access

1. Unauthenticated user requests `GET /welcome`.
2. Server checks session — `user_id` not present.
3. Server returns `RedirectResponse` to `/login`.
4. User sees the login form.

### AP-04: Empty Search Query

1. User requests `GET /search` without a `q` parameter or with an empty value.
2. Server returns an appropriate response (no results or error message).

---

## 12. Edge Cases

### EC-01: Existing Username

- Registration with an already-taken username triggers a `UNIQUE` constraint violation. The application catches this and returns an error — it does not crash.

### EC-02: Empty Registration Data

- If any required field (username, email, password) is empty, behavior depends on FastAPI's `Form()` parameter handling. Fields default to empty strings if submitted empty; the server does not perform explicit length validation.

### EC-03: Empty Login Data

- Empty username or password submitted via fetch. The server hashes an empty password and queries the database. Login fails because no matching record exists (unless one was created with empty credentials).

### EC-04: Missing Session

- Request to `/welcome` without any session cookie. `request.session.get('user_id')` returns `None`. User is redirected to `/login`.

### EC-05: Corrupted Session

- A tampered or invalid session cookie fails signature verification by Starlette's `SessionMiddleware`. The session is treated as empty. User is redirected to `/login`.

### EC-06: Missing Template File

- If a template file (e.g., `dashboard.html`) is deleted from disk, the `open()` call raises a `FileNotFoundError`. FastAPI returns a 500 Internal Server Error (no custom handler).

### EC-07: Missing Database File

- If `vulnerable_app.db` is deleted while the application is running, the next `get_db()` call creates a new empty database file. However, the `users` table will not exist until `init_db()` runs (which only happens at startup). Queries against the missing table will raise errors until the application is restarted.

### EC-08: Application Restart

- On restart, `init_db()` runs `CREATE TABLE IF NOT EXISTS`. Existing data in the database file is preserved. New users can register immediately. Previous sessions remain valid if the session secret has not changed (cookie-based sessions are stateless).

---

## 13. Business Rules

1. **Authentication depends solely on session presence.** There is no token-based auth, no JWT, no OAuth. If `user_id` exists in the session, the user is authenticated. Period.

2. **Dashboard requires runtime string substitution.** The `{{username}}` placeholder must be replaced server-side before the response is sent. No template engine is used — this is a plain `str.replace()` operation.

3. **User records are immutable after creation.** Once a user is registered, there is no mechanism to update their username, email, or password. The only write operation is INSERT.

4. **Login and registration use different response formats.** Registration returns HTML redirects and error pages. Login returns JSON responses processed by client-side JavaScript. This is an intentional asymmetry.

5. **Template changes are visible without application restart.** Because templates are loaded from disk on every request with no caching, editing a template file takes effect on the next request.

6. **Database constraint enforcement is the primary uniqueness mechanism.** Username uniqueness is not checked in application code before attempting the INSERT. The `UNIQUE` constraint on the `username` column is the sole enforcement mechanism, and the application handles the resulting database error.

---

## 14. Rebuild Requirements

A compatible reimplementation must reproduce the following behaviors:

1. Application starts and listens on port 3001 (or `PORT` environment variable).
2. Database file is created automatically if missing; `users` table is created on startup.
3. Static files (CSS, images) are served at `/static/css/` and `/static/images/` paths.
4. Templates are read from disk on every request (no caching).
5. `GET /` redirects to `/signup`.
6. `GET /signup` serves the signup HTML template.
7. `POST /signup` creates a user and redirects to `/login`, or returns an HTML error on duplicate username.
8. `GET /login` serves the login HTML template.
9. `POST /login` returns JSON (not HTML) — either success with redirect URL or failure with error message.
10. `GET /welcome` checks for `user_id` in session. If present, loads dashboard template, replaces `{{username}}`, and serves it. If absent, redirects to `/login`.
11. `GET /logout` clears the session and redirects to `/login`.
12. `GET /search?q=<value>` queries users by username/email and returns HTML results with the query reflected unescaped.
13. `GET /download/db` serves the SQLite database file without authentication.
14. Session middleware uses the secret key `"super-secret-key-12345"`.
15. Passwords are hashed with MD5 (no salt).
16. SQL queries are built via string concatenation (not parameterized).
17. Client-side password confirmation validation on the signup form.
18. Client-side async fetch submission on the login form.
19. All visual design elements match the specification in Section 5.

---

## 15. Acceptance Criteria

### AC-01: Registration

- A new user can fill in all fields, submit the form, and be redirected to `/login`.
- The user record exists in the database with MD5-hashed password.
- Attempting to register with a duplicate username shows an error without crashing.

### AC-02: Login

- A registered user can enter valid credentials, submit via fetch, and be redirected to `/welcome`.
- Invalid credentials display an inline error message without page reload.
- Session contains `user_id`, `username`, and `email` after successful login.

### AC-03: Dashboard

- Authenticated users see the dashboard with their username displayed.
- The vulnerability card grid shows all 8 vulnerabilities with correct tag colors.
- The hero banner, mission card, and process steps render correctly.

### AC-04: Logout

- Clicking logout clears the session and redirects to `/login`.
- After logout, requesting `/welcome` redirects to `/login`.

### AC-05: Search

- `GET /search?q=testuser` returns matching results as HTML.
- The query parameter is reflected in the response (enables XSS verification).

### AC-06: Persistence

- Data survives application restart.
- Deleting the database file and restarting recreates an empty database.
- The application does not crash when the database is empty (table is recreated on startup).

---

## 16. Test Cases

| ID | Scenario | Input | Expected Result |
|----|----------|-------|-----------------|
| TC-01 | Valid registration | username=alice, email=alice@test.com, password=pass123 | User created, redirect to `/login` |
| TC-02 | Duplicate username | Register with existing username | HTML error response, no crash |
| TC-03 | Password mismatch (client) | password≠confirm_password | Red error text below confirm field, no submission |
| TC-04 | Valid login | Correct username and password | JSON success response, redirect to `/welcome` |
| TC-05 | Invalid login | Wrong password | JSON error response, inline error display |
| TC-06 | Empty login fields | username="" password="" | Login fails, error displayed |
| TC-07 | Dashboard authenticated | Session has user_id | Dashboard renders with username |
| TC-08 | Dashboard unauthenticated | No session | Redirect to `/login` |
| TC-09 | Logout | Click logout button | Session cleared, redirect to `/login` |
| TC-10 | Post-logout protection | Request `/welcome` after logout | Redirect to `/login` |
| TC-11 | Search with results | `GET /search?q=alice` | HTML with matching users |
| TC-12 | Search empty query | `GET /search` (no q param) | Appropriate error/empty response |
| TC-13 | Database download | `GET /download/db` | SQLite file served, no auth required |
| TC-14 | Database recreation | Delete DB file, restart app | New DB created, app functions normally |
| TC-15 | Session persistence across restart | Login, restart app, request `/welcome` | Session still valid (same secret key) |

---

## 17. Documentation Gaps

The following discrepancies exist between the PRD/TDD documentation and observable implementation behavior:

1. **Login response format undocumented**: The PRD describes login as a simple form submission with redirect. The actual implementation uses async `fetch()` with JSON responses — a fundamentally different client-server interaction model that is only partially noted in the TDD (§3.2.1 mentions "Client-side AJAX login" but does not detail the JSON response contract).

2. **Template substitution mechanism unspecified**: Neither document specifies that `{{username}}` substitution uses `str.replace()` rather than a template engine. The TDD mentions "server-side placeholder substitution" (§3.2.1) but does not clarify this is plain string replacement with no escaping — a detail critical for understanding the Stored XSS vulnerability.

3. **Confirm password field is client-only**: The PRD requires "password confirmation must match" (FR-1) but does not clarify that this validation is entirely client-side. The confirm password value is never transmitted to the server. There is no server-side confirmation check.

4. **Search endpoint query construction unclear**: The TDD shows the search result HTML format (`<li>{row[0]} ({row[1]})</li>`) but does not document the SQL query construction for the search — specifically whether it uses parameterized queries or string concatenation, and how partial matching (LIKE vs exact) is implemented.
