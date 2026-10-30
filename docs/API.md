# API contract

Business endpoints at `/api/v1/auth/**` and `/api/v1/users/**` return JSON with the same keys on success and failure:

```json
{
  "success": false,
  "code": "VALIDATION_FAILED",
  "message": "Request validation failed",
  "data": null,
  "errors": [
    {"field": "password", "code": "ValidPassword", "message": "Password must contain at least 12 characters and at most 72 UTF-8 bytes"}
  ],
  "traceId": "12345678-1234-1234-1234-123456789abc",
  "timestamp": "2026-10-29T11:00:00Z"
}
```

On success, `success` is `true`, `data` contains the endpoint's result (or `null`), and `errors` is an empty array. HTTP status codes still carry their standard meaning. Clients should branch on `code` and field names rather than parsing English messages. A field can have multiple validation errors; `errors` contains every reported violation, with no rejected values. Global/body parsing errors use `code` and `message`, with an empty `errors` array.

`X-Request-Id` appears in response headers and matches `traceId`. The Gateway forwards it to backend services. Send an existing UUID in that header to correlate a request; missing or malformed values are replaced. This is a correlation identifier, not an authentication credential. `timestamp` is UTC.

JWKS (`/.well-known/jwks.json` on Auth) and Actuator retain their standard response formats. Successful CORS preflight returns HTTP 204 without a body. These protocol endpoints are intentionally excluded from the business response envelope.

## API versions

Business APIs use `/api/v1` on both the Gateway and the services. Unversioned `/auth/**` and `/users/**` URLs are no longer mapped. JWKS and Actuator URLs stay unchanged.

Java controllers and security matchers share version roots in `api-common`'s `ApiPaths`. Gateway routes in `api-gateway/src/main/resources/application.yml` have explicit version IDs (`auth-service-v1`, `user-service-v1`) and path predicates. To introduce v2 alongside v1, add `V2` roots, separate v2 controller mappings and security rules, and corresponding `/api/v2/**` Gateway routes. Keep v1 mappings while clients migrate.

## Endpoints

POST endpoints consume `application/json`, except `/api/v1/auth/logout-all`, which requires only a Bearer access JWT and no body.

| Endpoint | Request fields | Success | Data |
| --- | --- | --- | --- |
| `POST /api/v1/auth/register` | `email`, `password` | 201 `REGISTERED` | `id`, `email`, `emailVerified` |
| `POST /api/v1/auth/verify-email` | `email`, `otp` | 200 `EMAIL_VERIFIED` | `null` |
| `POST /api/v1/auth/resend-verification` | `email` | 200 `OTP_REQUESTED` | `null` |
| `POST /api/v1/auth/resend-otp` | `email` | 200 `OTP_REQUESTED` | `null` |
| `POST /api/v1/auth/forgot-password` | `email` | 200 `PASSWORD_RESET_REQUESTED` | `null` |
| `POST /api/v1/auth/reset-password` | `token`, `newPassword` | 200 `PASSWORD_RESET` | `null` |
| `POST /api/v1/auth/change-password` | Bearer JWT; `currentPassword`, `newPassword` | 200 `PASSWORD_CHANGED` | `null` |
| `POST /api/v1/auth/change-email` | Bearer JWT; `currentPassword`, `newEmail` | 200 `EMAIL_CHANGE_REQUESTED` | `null` |
| `POST /api/v1/auth/confirm-email-change` | `token` from new inbox | 200 `EMAIL_CHANGED` | `null` |
| `POST /api/v1/auth/login` | `email`, `password` | 200 `LOGGED_IN` | `accessToken`, `refreshToken`, `tokenType`, `expiresIn` |
| `POST /api/v1/auth/refresh` | `refreshToken` | 200 `TOKEN_REFRESHED` | Same token fields as login |
| `POST /api/v1/auth/logout` | `refreshToken` | 200 `LOGGED_OUT` | `null` |
| `POST /api/v1/auth/logout-all` | Bearer access token; no body | 200 `ALL_DEVICES_LOGGED_OUT` | `null` |
| `GET /api/v1/auth/sessions` | Bearer JWT; `sessions:read` | 200 `OK` | Owned active sessions |
| `DELETE /api/v1/auth/sessions/{id}` | Bearer JWT; `sessions:revoke` | 200 `SESSION_REVOKED` | `null` |
| `GET /api/v1/auth/devices` | Bearer JWT; `devices:read` | 200 `OK` | Owned device history |
| `DELETE /api/v1/auth/devices/{id}` | Bearer JWT; `devices:revoke` | 200 `DEVICE_REVOKED` | `null` |
| `POST /api/v1/auth/deactivate` | Bearer JWT; `currentPassword` | 200 `ACCOUNT_DEACTIVATED` | `null` |
| `GET /api/v1/auth/roles`, `GET /api/v1/auth/permissions` | Bearer JWT; `roles:manage` | 200 `OK` | Policy/catalog |
| `POST /api/v1/auth/roles`, `PUT /api/v1/auth/roles/{name}/permissions` | Admin JWT; `name`, `permissions`, `currentPassword` | 200 `ROLE_UPDATED` | Role definition |
| `PUT /api/v1/auth/users/{id}/roles` | Admin JWT; `roles`, `currentPassword` | 200 `ROLES_UPDATED` | Assigned roles |
| `GET /api/v1/users/me` | Bearer JWT; `profile:read` | 200 `OK` | `id`, `roles`, profile fields/version |
| `PATCH /api/v1/users/me` | Bearer JWT; `profile:write`; partial profile fields | 200 `OK` | Updated profile |

Logout now returns **200 with JSON**, replacing the earlier 204 response. Tokens now live under `data`, for example `response.data.accessToken`.

Mail runs a separate internal API on port `8703` at `/api/v1/mail/**`, authenticated by `X-Mail-Service-Key`. It is not routed through the Gateway. See [Mail service](MAIL_SERVICE.md) for its endpoints, template configuration, and failure behavior.

## Input validation

- Email is required, normalized by trimming and lowercasing, validated as an email address, and limited to 254 characters.
- Registration passwords are required, contain at least 12 Unicode code points, and fit within BCrypt's 72 UTF-8 byte limit. Passwords are not trimmed or normalized. No additional character-composition rule is imposed.
- Login passwords are required and limited to 72 UTF-8 bytes. Password creation policy is separate from login validation.
- OTP is a required string of exactly six ASCII digits. Leading zeros are preserved.
- Refresh tokens are required strings of exactly 43 base64url characters, matching tokens generated by Auth.
- Missing/empty bodies, malformed JSON, unknown fields, duplicate keys, trailing JSON, wrong JSON types, and scalar coercion (such as numeric OTP) are rejected. JSON parsing is bounded to 20 nesting levels, 4096 characters per string, and 128 characters per number.
- OTP expiry, attempts, cooldown, account verification, duplicate registration, password comparison, and refresh-token reuse are checked as business rules after form validation.

## Error codes

| HTTP status | Codes |
| --- | --- |
| 400 | `VALIDATION_FAILED`, `INVALID_REQUEST`, `INVALID_OTP`, `INVALID_ACCOUNT_TOKEN`, `PASSWORD_UNCHANGED`, `EMAIL_UNCHANGED`, `INVALID_ROLE_POLICY` |
| 401 | `UNAUTHENTICATED`, `INVALID_CREDENTIALS`, `INVALID_REFRESH_TOKEN` |
| 403 | `ACCESS_DENIED`, `EMAIL_NOT_VERIFIED`, `HOST_NOT_ALLOWED`, `ORIGIN_NOT_ALLOWED`, `CORS_REJECTED` |
| 404 | `NOT_FOUND` |
| 405 | `METHOD_NOT_ALLOWED` |
| 409 | `EMAIL_EXISTS`, `CONFLICT` |
| 415 | `UNSUPPORTED_MEDIA_TYPE` |
| 429 | `OTP_COOLDOWN`, `OTP_ATTEMPTS_EXCEEDED`, `TOO_MANY_REQUESTS`, `RATE_LIMITED`, `ACCOUNT_TEMPORARILY_LOCKED`, `ACCOUNT_ACTION_COOLDOWN`, `SESSION_LIMIT_REACHED` |
| 500 | `INTERNAL_ERROR` |
| 502 | `UPSTREAM_UNAVAILABLE` |
| 503 | `EMAIL_NOT_CONFIGURED`, `EMAIL_DELIVERY_FAILED`, `SECURITY_UNAVAILABLE`, `SERVICE_UNAVAILABLE` |
| 504 | `UPSTREAM_TIMEOUT` |

Known business failures have public catalog messages. Unexpected failures return a generic message; exception text, SQL, provider responses, and stack traces are excluded from the response. Missing and invalid JWTs use the same shared envelope in every service. JWT signature validation is local; P2 also checks live account/session state and current permissions through Auth. User owns profile data in a separate database.

## P1 account lifecycle

Verification/resend keep their existing one-time hashed OTPs; `resend-verification` aliases `resend-otp`. Forgot-password responds generically before lookup/delivery using a durable encrypted SQL outbox. Reset and email-change tokens are random, single-use opaque values with a 15-minute TTL and SHA-256 hashes in SQL. Authenticated password/email changes require the current password. Confirming the new inbox is required before replacing the account email. Reset/change invalidates pending lifecycle proofs and all refresh sessions; P2 state checks also reject previously issued JWTs after invalidation.

Every email template includes a Mail-managed signature configured with `MAIL_SIGNATURE`. See [P1 account lifecycle](ACCOUNT_LIFECYCLE_P1.md) for request/response behavior, cooldowns, concurrency, and notification delivery.

## P0 authentication controls

Refresh rotation is atomic across Auth instances. Reusing a consumed token revokes its whole family; clients must serialize refresh attempts. Refresh families have a seven-day absolute expiry. Logout-all invalidates all existing refresh generations for the JWT subject; P2 live state checks reject invalidated JWTs before their cryptographic expiry.

Login rate limiting and temporary lockout return HTTP 429 with `Retry-After` and stable `RATE_LIMITED` / `ACCOUNT_TEMPORARILY_LOCKED` codes. Redis security failures return HTTP 503 (`SECURITY_UNAVAILABLE`). Gateway and Auth share an `AUTH_PROXY_KEY` generated during preparation for trustworthy client-IP propagation. See [P0 security hardening](SECURITY_P0.md) for configuration, migration, key-rotation commands, and audit events.

## Gateway host and origin policy

Set these in `.env`, then restart the services:

```dotenv
GATEWAY_ALLOWED_HOSTS=localhost,127.0.0.1,[::1]
GATEWAY_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
GATEWAY_REQUIRE_ORIGIN=false
```

`GATEWAY_ALLOWED_HOSTS` is the exact list of API hostnames in the incoming `Host` header, without scheme or port. It identifies the requested API hostname, not the caller's hostname. `GATEWAY_ALLOWED_ORIGINS` is the exact list of frontend origins including scheme and optional port, without a trailing slash or path. Wildcards are rejected at startup. Configure actual deployment domains before exposing the Gateway.

Unknown hosts and supplied unknown origins are rejected before proxying, even outside a browser. CORS allows GET, POST, PATCH, PUT, DELETE, OPTIONS and the Authorization, Content-Type, X-Device-Id, X-Request-Id headers. Only approved origins receive CORS response headers; `X-Request-Id` and `Retry-After` are exposed for browser clients. Cookies/credentialed CORS are disabled because the current API uses Bearer tokens.

When `GATEWAY_REQUIRE_ORIGIN=false`, requests without Origin can be made by terminal/API clients and health checks. When `true`, API requests also require an approved Origin; GET `/actuator/health` remains available without it. Client-supplied Forwarded/X-Forwarded headers are removed before host checking; the application does not derive the trusted host from them.

Host and Origin are not caller authentication: non-browser clients can set both. Protected endpoints continue to require JWT. Restrict network access or use mTLS/client authentication if only specific backend callers should connect. Auth/User bind to `127.0.0.1` by default to avoid bypassing the Gateway remotely; a private-network deployment can explicitly set `SERVICE_BIND_ADDRESS`.

## P2 state checks and profile ownership

Gateway and User validate JWTs locally, then call Auth's private `/internal/identity/check` using `IDENTITY_SERVICE_KEY`. Auth checks account activation, credential revision, refresh-family state and session generation, and returns live role permissions. Denied identities return 401; unavailable remote checks fail closed with 503. This endpoint is not routed through Gateway. Profile data is stored only in User's `userdb`; identity/role/device data remains in Auth's `authdb`. See [P2 session and identity management](SESSION_IDENTITY_P2.md).

## Reuse in another service

- `api-common` owns the response contract, error-code interface, exception, trace utilities, structured log helpers, email normalization, and shared validation constraints.
- `api-servlet` depends on `api-common` and supplies Boot auto-configuration for MVC exception handling, security error writers, request tracing, fallback errors, and strict JSON parsing. Auth and User depend on this module.
- `api-reactive` depends on `api-common` and supplies Boot auto-configuration for WebFlux exception handling, security error writers, and request tracing. Gateway depends on it; it does not load the Servlet stack.

Add the matching dependency, implement `ApiCode` in a service-specific enum for domain messages, throw `ApiException(code)`, and return `ServletApi.success(code, data)` from business controllers. Configure Spring Security with the injected `ServletSecurityErrors` (or `ReactiveSecurityErrors`) for both exception handling and OAuth2 resource-server failures. New services receive the common behavior through Boot auto-configuration, without copying handlers.

Application log helpers emit event, stable code, status/duration, exception class and traceId. They exclude raw request bodies, credentials, OTPs, tokens and provider exception messages. Auth DTO/token `toString()` methods redact sensitive values. Framework DEBUG/TRACE logging is separate and can expose request/exception contents; use normal application logging for credentials-bearing traffic.

Last-admin removal returns `409 LAST_ADMINISTRATOR`. Mail delivery is asynchronous from Auth; a successful lifecycle response confirms durable enqueue. Internal Mail accepts a UUID `Idempotency-Key` and rejects different content under the same ID with 409. See [hardening operations](HARDENING_RELIABILITY.md).

## Account access extension

See [ACCOUNT_ACCESS.md](ACCOUNT_ACCESS.md) for the added admin/status, introspection, history, trusted-device, scoped API-key, tenant profile policy, export and deletion APIs. The executable [OpenAPI specification](openapi.json) covers these public endpoints.

Canonical management endpoints use `/api/v1/auth`: `GET /users`, `PATCH /users/{id}/status`, `PUT /users/{id}/roles`, `GET/POST /roles`, `PUT /roles/{name}/permissions`, `POST /reauthenticate`, `GET /login-history`, `GET /session/current`. Self-service account endpoints are `DELETE /api/v1/users/me` and `GET /api/v1/users/me/export`. GET export requires `X-Reauthentication-Token` obtained from password reauthentication; DELETE still requires `currentPassword` in its JSON body. See the account-access guide for compatibility aliases and request schemas.
