# Hybrid Auth Microservices Lab

A runnable *learning/reference implementation* of JWT access tokens, opaque rotating refresh tokens, Redis-backed refresh sessions, PostgreSQL users, and a JWT-validating Spring Cloud Gateway. No Docker Desktop required; Docker CLI with a working daemon is sufficient.

API response schema, validation rules, error codes, Gateway allowlists, and shared-module usage: [API contract](docs/API.md).

P1 account recovery, password/email changes, and signed email templates: [Account lifecycle](docs/ACCOUNT_LIFECYCLE_P1.md).

P0 controls, Redis session lifecycle, rate limits, lockout, key rotation, and audit operations: [Security hardening](docs/SECURITY_P0.md).

Mail API, HTML templates, and integration guide: [Mail service](docs/MAIL_SERVICE.md).

Source packages and folder responsibilities: [Project structure](docs/PROJECT_STRUCTURE.md).

## Current architecture

The local setup runs four Java services on the host and two data stores in Docker Compose. Clients call the Gateway at port `8700`; Auth and User bind to `127.0.0.1` by default. The internal Mail service binds to `127.0.0.1:8703` by default and owns the external SMTP connection configured through `.env`.

```mermaid
flowchart LR
    client["API client / frontend"]

    subgraph host["Host — Java services"]
        gateway["API Gateway :8700<br/>Spring Cloud Gateway / WebFlux<br/>Host and origin allowlists, CORS, JWT validation"]
        auth["Auth service :8701<br/>Spring MVC<br/>Email OTP, login, refresh, logout<br/>Password recovery and account changes"]
        user["User service :8702<br/>Spring MVC<br/>JWT validation and current-user profile"]
        mail["Mail service :8703<br/>Spring MVC / internal API key<br/>Template catalog, HTML preview, SMTP delivery"]
        keys["RSA keys<br/>Private JWK manifest with active kid<br/>PEM compatibility fallback"]
    end

    subgraph docker["Docker Compose — persistent volumes"]
        postgres[("PostgreSQL :5432<br/>Users, email OTP hashes<br/>Reset and email-change token hashes")]
        redis[("Redis :6379<br/>Refresh tokens, families, generations<br/>Rate limits and login lockout")]
    end

    smtp["External SMTP provider"]
    inbox["User email inbox"]

    client -->|"HTTP /api/v1/**"| gateway
    gateway -->|"/api/v1/auth/**"| auth
    gateway -->|"/api/v1/users/** + Bearer JWT"| user
    gateway -.->|"Fetch public keys via JWKS"| auth
    user -.->|"Fetch public keys via JWKS"| auth
    keys -->|"Load keys and poll manifest for rotation"| auth
    auth -->|"JPA / Flyway"| postgres
    auth -->|"Atomic rotation, reuse detection, revoke sessions"| redis
    auth -->|"HTTP /api/v1/mail/send + internal key"| mail
    mail -->|"Render HTML/text template and send over TLS"| smtp
    smtp -->|"Verification email"| inbox
```

Solid arrows show request/data connections; dotted arrows show public-key retrieval. Gateway and User use Auth's `/.well-known/jwks.json` endpoint to validate JWTs locally. Auth validates JWTs with its configured RSA public key. All three validate issuer and the `hybrid-api` audience. User currently builds `/api/v1/users/me` from the JWT subject and roles; it has no database dependency.

| Component | Responsibility |
| --- | --- |
| `api-gateway` | Enforce host/origin allowlists and CORS, validate JWTs for protected requests, and forward versioned routes to Auth or User. Only the explicit verification, recovery, login, refresh, and logout endpoints are public; their handlers validate credentials, OTPs, or refresh tokens as appropriate. |
| `auth-service` | Store users, hashed lifecycle tokens, and BCrypt password/OTP hashes in PostgreSQL, request verification email synchronously through Mail, sign RS256 access JWTs using a reloadable key ring, enforce rate limits/temporary lockout, and manage refresh sessions atomically in Redis. Flyway maintains the database schema. |
| `mail-service` | Own SMTP credentials, the configured HTML/text template catalog, required variables, preview rendering, and synchronous multipart email delivery. Internal API on port `8703`, protected with a shared service key; no Gateway route or database. |
| `user-service` | Independently validate access JWTs and return the current user's ID and roles. |
| PostgreSQL | Persist user identity, verification state, OTP hashes, expiry, cooldown, and attempt counts in the `authdb` database. |
| Redis | Store SHA-256 refresh-token hashes, family state, user session generations, shared IP rate counters, and temporary login locks. Refresh families have a seven-day absolute expiry. |

### Authentication flow

1. **Register:** `POST /api/v1/auth/register` creates an unverified user, generates a six-digit OTP, and calls Mail with the `email-verification` template and variables. Mail renders HTML with a text alternative and submits it to SMTP. The response contains registration data, without tokens. Failed email delivery returns HTTP 503 and rolls back registration.
2. **Verify:** `POST /api/v1/auth/verify-email` verifies the OTP against its stored hash and marks the email verified. Codes expire after five minutes and allow five attempts; `/api/v1/auth/resend-otp` replaces the code after a 60-second cooldown.
3. **Login:** `POST /api/v1/auth/login` checks the BCrypt password and email verification state, then returns a 15-minute RS256 access JWT and an opaque refresh token. The refresh family has a seven-day absolute lifetime; incorrect passwords trigger temporary lockout.
4. **Access a protected API:** send `Authorization: Bearer <accessToken>` to `GET /api/v1/users/me`. Gateway validates the token before forwarding it; User validates it again and reads its claims. This request does not query PostgreSQL or Redis.
5. **Refresh or logout:** `POST /api/v1/auth/refresh` reloads the user from PostgreSQL and atomically rotates the current refresh token in Redis. Reuse revokes the entire family. `POST /api/v1/auth/logout` uses the current refresh token to revoke that family's refresh sessions. `POST /api/v1/auth/logout-all` requires an access JWT and revokes all of that user's refresh families by advancing its session generation. Existing access JWTs remain valid until expiry.

### Shared modules

Arrows below mean “depends on.” These modules are libraries packaged with the services, not separate running services.

```mermaid
flowchart TB
    auth["auth-service"] --> servlet["api-servlet<br/>MVC response helpers, validation configuration,<br/>exception/security handlers, request tracing"]
    user["user-service"] --> servlet
    mail["mail-service"] --> servlet
    gateway["api-gateway"] --> reactive["api-reactive<br/>WebFlux response helpers,<br/>exception/security handlers, request tracing"]
    servlet --> common["api-common<br/>ApiPaths, response envelope, status codes,<br/>validation, exceptions, trace and logging helpers"]
    reactive --> common
```

Servlet and reactive adapters auto-configure for their respective web stacks. Business responses share the same JSON envelope and `X-Request-Id` correlation header. JWKS and Actuator retain their standard response formats.

Business endpoints use `/api/v1` in both Gateway routes and service mappings. Java controllers and security matchers share roots in [`ApiPaths`](api-common/src/main/java/dev/kaidev/common/api/ApiPaths.java); Gateway routes are declared in [`application.yml`](api-gateway/src/main/resources/application.yml). Future `/api/v2` controllers and routes can coexist with v1; see [API versions](docs/API.md#api-versions).

## Prerequisites
- Docker Engine / Colima / OrbStack with Docker Compose v2
- OpenSSL, JDK 25, Maven, Python 3
- VS Code with the recommended Java Extension Pack (see `.vscode/extensions.json`)

## Local run/debug with VS Code
Docker runs only PostgreSQL and Redis by default. Mail, Auth, User, and Gateway run on the host through VS Code.

1. Open this repository root in VS Code and install the recommended Java extensions.
2. Run **Developer: Reload Window** after changing the Java settings and let Maven import finish.
3. Open **Run and Debug**, choose **All Services (Local)**, then press **F5** to debug or **Ctrl+F5** to run without debugging. The prepare task reuses existing JWT keys (or creates them when missing), starts both databases, and waits until they are healthy.
4. Set breakpoints in any service, for example `ProfileController.me`, and send requests through `http://localhost:8700`.

| Component | Local address |
| --- | --- |
| Gateway | `http://localhost:8700` |
| Auth service | `http://localhost:8701` |
| User service | `http://localhost:8702` |
| Mail service (internal) | `http://127.0.0.1:8703` |
| PostgreSQL | `127.0.0.1:5432`, database `authdb`, user `auth` |
| Redis | `127.0.0.1:6379` |

The default local database password is `authdev`. The local `.env` is created from `.env.example`; update `DB_PASSWORD` there before first database startup. Compose and the Auth launch configuration use the same file. For an existing PostgreSQL volume, changing this variable does not change the stored database password.

To launch services individually, first run **Tasks: Run Task → local: prepare**, then choose **Auth Service**, **User Service**, **Gateway**, or **Mail Service** in Run and Debug. Wait for all services to finish startup before sending API requests. Stopping **All Services (Local)** stops all four Java processes; the databases stay running. Use **Tasks: Run Task → local: databases stop** to stop them without deleting data.

The workspace selects the JDK 25 already installed on this Mac at `/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home` for Java tooling and new integrated terminals. On another machine, update the JDK paths in `.vscode/settings.json`. If an individual service or VS Code cannot resolve `dev.kaidev.common`, run **Tasks: Run Task → maven: install shared modules** to install the parent POM and shared libraries into Maven local. After package moves, close tabs pointing to the old paths and reopen files from Explorer. If Java diagnostics remain stale, run **Java: Clean Java Language Server Workspace** and reload.

Run all services from a terminal:
```bash
./run-services.sh
```

The script runs `prepare-env.sh` to create `.env` if missing and generate `MAIL_SERVICE_API_KEY` and `AUTH_PROXY_KEY` when empty, runs `prepare-jwt.sh` to initialize the reloadable manifest from existing JWT keys, starts PostgreSQL and Redis with Docker Compose, runs `mvn verify`, then launches Mail first, followed by Auth, User, and Gateway. It waits for each health endpoint before continuing. Logs are written to `logs/`. Press **Ctrl+C** to stop all Java services; databases keep running. Stop them with `docker compose stop`.

Use JDK 25 (`JAVA_HOME`); on macOS the script also detects the Homebrew JDK used by this workspace. Docker Compose contains only PostgreSQL and Redis.

The tasks **local: prepare**, **local: databases up**, **local: databases stop**, and **maven: verify** are also available from **Tasks: Run Task**. **Cmd+Shift+B** runs Maven verification on macOS.

## Email verification configuration
Mail owns the SMTP settings. Auth calls it using `MAIL_SERVICE_URL` and the same `MAIL_SERVICE_API_KEY`. Both `./run-services.sh` and the VS Code prepare task generate this key in `.env` when missing; for manual launches run `bash ./prepare-env.sh` first. SMTP credentials are intentionally left empty:
```dotenv
MAIL_SERVICE_URL=http://127.0.0.1:8703
MAIL_SERVICE_PORT=8703
# MAIL_SERVICE_API_KEY is generated in .env by prepare-env.sh
SMTP_HOST=
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=
SMTP_PASS=
EMAIL_FROM=""
```
`SMTP_SECURE=false` uses STARTTLS (normally port 587); `true` uses implicit TLS (normally port 465). `EMAIL_FROM` accepts `Team Name <sender@example.com>`. Restart the services after editing `.env`. The shell runner loads these keys; the VS Code Auth and Mail launches also read `.env`. SMTP is configured only in Mail. Direct Maven/Java launches need these variables exported.

Mail includes eight signed HTML/text templates for verification, welcome, password recovery/change, and email changes. Configure their shared footer using `MAIL_SIGNATURE` (default: `Hybrid Auth Security Team`). See [Mail service](docs/MAIL_SERVICE.md) to list, preview, send, or configure another template. Template changes require restarting Mail. `welcome` is available to callers but is not sent automatically during registration.

Registration sends a six-digit email OTP and returns `emailVerified: false`, without tokens. Login and refresh require a verified email. Existing accounts must request an OTP with `/api/v1/auth/resend-otp` before logging in again; previously issued access tokens remain valid until expiry. OTPs expire after five minutes, allow five attempts, and are stored as hashes. Resending requires a 60-second wait and replaces the previous code. Missing SMTP configuration or mail delivery failure returns HTTP 503; failed registration is rolled back so it can be retried.

## Functional test
Business APIs use the `/api/v1` prefix. See [API versions](docs/API.md#api-versions) for adding future versions.
Registration passwords must contain at least 12 characters and at most 72 UTF-8 bytes. Validation errors return HTTP 400 with field messages in the `errors` array; all business responses use the shared [API contract](docs/API.md).
```bash
curl -i -X POST http://localhost:8700/api/v1/auth/register -H 'Content-Type: application/json' -d '{"email":"test@example.com","password":"StrongPassword123!"}'
# Read the OTP from your email and verify before logging in:
curl -i -X POST http://localhost:8700/api/v1/auth/verify-email -H 'Content-Type: application/json' -d '{"email":"test@example.com","otp":"123456"}'
# Optional: request a new code after 60 seconds:
# curl -i -X POST http://localhost:8700/api/v1/auth/resend-otp -H 'Content-Type: application/json' -d '{"email":"test@example.com"}'
curl -s -X POST http://localhost:8700/api/v1/auth/login -H 'Content-Type: application/json' -d '{"email":"test@example.com","password":"StrongPassword123!"}'
```
Copy `data.accessToken` from the login JSON, then call:
```bash
curl http://localhost:8700/api/v1/users/me -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'
```
Refresh via `POST /api/v1/auth/refresh` with `{"refreshToken":"..."}`; call `POST /api/v1/auth/logout` with a refresh token to revoke its family. Use `POST /api/v1/auth/logout-all` with a Bearer access JWT to revoke every device's refresh sessions. Login / refresh responses return tokens in JSON for API debugging; do not store these in localStorage in a browser app.

## Account lifecycle (P1)

Email verification/resend reuse the existing OTP implementation; `/api/v1/auth/resend-verification` is an alias for `/resend-otp`. New endpoints are `/forgot-password`, `/reset-password`, `/change-password`, `/change-email`, and `/confirm-email-change` under `/api/v1/auth`.

Forgot-password returns a generic response before account lookup/mail delivery using a bounded in-memory worker queue. Reset and email-change proofs are single-use opaque tokens, stored only as hashes with a 15-minute TTL. Password/email changes require a Bearer JWT and the current password; the new email becomes active only after its inbox confirms the change. Completed changes revoke all refresh sessions and send signed security notifications. See [P1 account lifecycle](docs/ACCOUNT_LIFECYCLE_P1.md) for request fields, failure behavior, and templates.

## Scope / security limitations
- Lab returns refresh tokens in JSON. For production browser deployment implement a BFF or HttpOnly Secure SameSite cookie, CSRF protection for cookie authentication, and a tested reverse proxy/TLS termination.
- Refresh operations and abuse controls use atomic Redis scripts across Auth instances. Security-state operations fail closed when Redis is unavailable. Durable Redis state and consistent recovery remain deployment requirements; see [P0 operations](docs/SECURITY_P0.md).
- `logout` and `logout-all` revoke future refresh only; previously issued access JWTs remain valid until expiry (15 minutes). Critical revocation needs a short-lived access TTL or introspection/denylist.
- Mail service delivery is synchronous, without a durable queue, outbox, automatic retries, or persistent delivery history. Auth uses a bounded in-memory queue for forgot-password requests and best-effort after-commit change notifications. An SMTP success means provider acceptance; it does not confirm inbox delivery. A timeout after provider acceptance can leave the caller uncertain whether mail was sent.
- No MFA, centralized immutable audit store, distributed tracing, or secret-manager integration yet. P0 provides shared rate limiting/temporary lockout, file-based JWT key rotation, and local rolling JSON audit logs.
- Demo credentials and keys are for local development only. Private keys are excluded from git; local preparation imports the existing RSA key into a private, reloadable JWK manifest under `keys/`.
- Backend services should not be publicly exposed; retain private network access and service-level JWT verification.
