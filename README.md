# Vulnerable Web Application Build via Claude Code

An intentionally vulnerable web application designed to teach common security vulnerabilities through hands-on exploitation. Rather than studying vulnerabilities in theory, you'll exploit them in a working application to understand how real attacks work.

Built with FastAPI and SQLite — simple enough to read in one sitting, realistic enough to demonstrate actual attack techniques.

**Live Demo:** https://vuln-web-app.onrender.com

> **WARNING:** This application is deliberately insecure. It is designed for educational use only and should never be deployed to production or used on systems you do not own.

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | FastAPI, Uvicorn |
| Database | SQLite3 |
| Frontend | Vanilla HTML5, CSS3, JavaScript |
| Session Management | Starlette SessionMiddleware |
| Package Manager | uv |
| Python | 3.12+ |

## Project Structure

```
vuln-web-app/
├── backend/
│   ├── app/
│   │   ├── main.py                  # Entry point — starts the server
│   │   ├── core/
│   │   │   └── security.py          # Password hashing (bcrypt, work factor 12)
│   │   ├── db/
│   │   │   └── session.py           # Database connection and schema setup
│   │   ├── services/
│   │   │   └── auth_service.py      # Business logic for signup and login
│   │   └── api/routes/
│   │       └── auth.py              # All HTTP route handlers
│   └── pyproject.toml               # Backend package config
├── frontend/
│   ├── templates/
│   │   ├── login.html               # Login page (fetch-based, theme toggle)
│   │   ├── signup.html              # Registration page (form POST, theme toggle)
│   │   └── dashboard.html           # Protected dashboard (theme toggle)
│   └── static/
│       ├── css/styles.css           # Application styling (light/dark themes)
│       └── images/                  # Organization logos (PUCIT, Excaliat, FCCU)
├── docs/
│   ├── PRD.md                       # Product requirements
│   ├── TDD.md                       # Technical design
│   └── prompts/                     # Prompts used to generate specs & plans
├── .claude/specs/                   # Feature specs and implementation plans
├── pyproject.toml                   # Root project config
└── vulnerable_app.db                # SQLite database (auto-created)
```

---

## Getting Started

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager

### Installation

```bash
# Clone the repository
git clone https://github.com/arifpucit/vuln-web-app.git
cd vuln-web-app

# Install dependencies
uv sync
```

### Running the Application

From the project root:
```bash
uv run backend/app/main.py
```

The app starts at **http://localhost:3001**. The database file (`vulnerable_app.db`) is created automatically on first run.

---

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|:---:|
| GET | `/` | Redirect to signup | No |
| GET | `/signup` | Display signup form | No |
| POST | `/signup` | Create user account | No |
| GET | `/login` | Display login form | No |
| POST | `/login` | Authenticate user (returns JSON) | No |
| GET | `/welcome` | Protected dashboard | Yes |
| GET | `/logout` | Terminate session | No |
| GET | `/search?q=` | Search users | No |
| GET | `/download/db` | Download database file | No |

---

## Intentional Vulnerabilities

| # | Vulnerability | OWASP Category | Location | Status |
|---|---------------|----------------|----------|--------|
| 1 | SQL Injection | A03:2021 - Injection | `auth_service.py` — string concatenation in queries | Open |
| 2 | Stored XSS | A03:2021 - Injection | `auth.py` — unescaped username on dashboard | Open |
| 3 | Reflected XSS | A03:2021 - Injection | `auth.py` — unescaped query param in search | Open |
| 4 | Session Hijacking | A07:2021 - Auth Failures | `main.py` — hardcoded secret key | Open |
| 5 | Weak Password Storage | A02:2021 - Crypto Failures | `security.py` — was MD5 (no salt); now bcrypt (cost 12) | **Closed** |
| 6 | Exposed Database | A01:2021 - Access Control | `auth.py` — unauthenticated `/download/db` | Open |
| 7 | No Rate Limiting | A07:2021 - Auth Failures | Global — no throttling middleware | Open |
| 8 | CSRF | A01:2021 - Access Control | Global — no CSRF tokens on forms | Open |

### Fix Notes — Vulnerability #5 (Bcrypt)

- `security.py` now uses bcrypt with `BCRYPT_ROUNDS = 12`. `hash_password()` returns a 60-char `$2b$12$…` string; `verify_password()` wraps `bcrypt.checkpw` in `try/except` so a legacy MD5 row returns `False` instead of crashing.
- `auth_service.login()` no longer embeds the password hash in the SQL `WHERE` clause (bcrypt can't be matched with `=`). It fetches the user by username and compares with `verify_password()` in Python. The username branch of that query **remains string-concatenated**, so VULN-1 is unchanged.
- After pulling this change, run `uv sync` to install `bcrypt`, then delete `vulnerable_app.db` and re-register — legacy MD5 accounts can no longer authenticate.

---

## Features

- User registration with client-side password confirmation
- User login via async fetch with inline error display
- Protected dashboard with personalized greeting
- Vulnerability discovery checklist with color-coded tags
- Responsive split-screen layout for auth pages
- University-branded header with organization logos
- SQLite database with automatic initialization
- Database auto-recreated if deleted (on restart)
- **Light / dark theme toggle** on login, signup, and dashboard pages — preference saved in `localStorage` under the key `theme`, restored before first paint to avoid FOUC, falls back to `prefers-color-scheme`, keyboard accessible, themed via CSS custom properties and a `data-theme` attribute on `<html>`

---

## Learning Path

1. **Explore the app** — Sign up, log in, and navigate the dashboard to understand normal functionality.
2. **Read the source code** — Each vulnerability is commented in the code with its vulnerability number.
3. **Exploit each flaw** — Use the vulnerability table above to locate and exploit each one.
4. **Fix it** — Patch each vulnerability using secure coding practices: parameterized queries, output escaping, strong password hashing, rate limiting, and CSRF tokens.

---

## Useful Commands

Check the database contents:
```bash
sqlite3 vulnerable_app.db "SELECT * FROM users;"
```

Reset the database (delete and restart):
```bash
rm vulnerable_app.db
uv run backend/app/main.py
```

Free port 3001 if already in use:
```bash
# macOS / Linux
lsof -ti:3001 | xargs kill

# Windows (PowerShell)
Get-NetTCPConnection -LocalPort 3001 | Select-Object OwningProcess
Stop-Process -Id <PID> -Force
```

---

## Troubleshooting

**`uv command not found`**
Install uv: `pip install uv` or see https://docs.astral.sh/uv/getting-started/installation/

**`Port 3001 already in use`**
Kill the existing process using the commands in "Useful Commands" above.

**`ModuleNotFoundError: No module named 'app'`**
Run the app from the project root with `uv run backend/app/main.py`. The entry point automatically adds `backend/` to `sys.path`.

**Database seems corrupted or stale**
Delete `vulnerable_app.db` from the project root and restart the app. The database is recreated automatically on startup.

---

## Future Enhancements

### Completed

| # | Feature / Fix | Branch | Notes |
|---|---------------|--------|-------|
| 1 | Dark Mode Toggle | `feature/dark-mode-toggle` | Light/dark themes with `localStorage` persistence, `prefers-color-scheme` fallback, no FOUC; see `.claude/specs/dark-mode-toggle.md` |
| 2 | Bcrypt Password Hashing | `fix/bcrypt-password-hashing` | Closes VULN-5. MD5 replaced with bcrypt (cost 12); `login()` verifies in Python; see `.claude/specs/bcrypt-password-hashing.md` |

### Feature Enhancements

| # | Feature | Description |
|---|---------|-------------|
| 1 | Remember Me Checkbox | Keep session alive across browser restarts using persistent cookies |
| 2 | Password Strength Meter | Real-time visual indicator showing password strength during signup |
| 3 | Forgot Password (Email Link) | Send a password reset link to the user's registered email |
| 4 | Email Verification on Signup | Send a verification email with a token link before activating the account |
| 5 | User Profile Page | View and edit username, email, and avatar from a settings page |
| 6 | Change Password | Allow authenticated users to update their password from the profile page |
| 7 | Continue with Google (OAuth 2.0) | Sign up and login using Google account via OAuth 2.0 flow |
| 8 | Continue with GitHub (OAuth 2.0) | Sign up and login using GitHub account via OAuth 2.0 flow |
| 9 | Role-Based Access Control | Add admin and user roles with different dashboard permissions |
| 10 | MFA via Authenticator App (TOTP) | Enable two-factor auth using Google Authenticator or Authy with QR code setup |
| 11 | MFA Recovery Codes | Generate and display one-time backup codes during MFA enrollment |
| 12 | OTP via Email | Send a one-time passcode to the user's email as a second authentication factor |
| 13 | OTP via SMS | Send a one-time passcode to the user's registered phone number via Twilio |
| 14 | QR Code Login | Scan a QR code on the login page from an authenticated mobile device to log in |
| 15 | Session Management Dashboard | View and revoke active sessions across devices from the profile page |
| 16 | Account Lockout | Lock the account after N failed login attempts with a cooldown timer |
| 17 | Rate Limiting | Throttle requests per IP/user using middleware to prevent brute force attacks |
| 18 | CAPTCHA on Login | Add Google reCAPTCHA or hCaptcha to the login form after failed attempts |
| 19 | Audit Log | Record and display login attempts, password changes, and security events |
| 20 | CSRF Protection | Add CSRF tokens to all forms to prevent cross-site request forgery |
| 21 | Content Security Policy | Set CSP headers to mitigate XSS and injection attacks |
| 22 | Account Deletion | Allow users to permanently delete their account and all associated data |
| 23 | Admin User Management | Admin panel to view, deactivate, or delete user accounts |
| 24 | API Key Authentication | Generate and manage personal API keys for programmatic access |
| 25 | Magic Link Login | Passwordless login via a one-time link sent to the user's email |
| 26 | Passkey / WebAuthn | Register and authenticate using biometrics or hardware security keys |
| 27 | SSO with SAML | Enterprise single sign-on integration using SAML 2.0 protocol |

### Bug Fixes

| # | Issue | Description |
|---|-------|-------------|
| 1 | No Server-Side Password Confirmation | Confirm password is only validated client-side; server accepts any POST without matching check |
| 2 | No Email Format Validation | Email field accepts any non-empty string with no format or domain validation |
| 3 | No Password Strength Enforcement | No minimum length, complexity, or character requirements on passwords |
| 4 | Empty Field Registration | Server allows registration with whitespace-only fields that pass the non-empty check |
| 5 | No Connection Pooling | Each database operation opens a new SQLite connection instead of reusing from a pool |
| 6 | Error Messages Leak Information | SQL errors and stack traces exposed to users via search endpoint error responses |
| 7 | No Input Length Limits | Username, email, and password fields have no maximum length restriction |
| 8 | Session Never Expires | Sessions persist indefinitely with no timeout or expiration mechanism |

---

## Legal Notice

This application is provided strictly for educational purposes. Unauthorized access to computer systems is illegal. Ensure you have explicit permission before testing security vulnerabilities on any system you do not own. The authors are not responsible for misuse of this project.
