# Account access extension

This extension adds the missing capabilities to P2 and keeps its role assignments, live identity checks, owned sessions/devices, password-change notifications and profile fields. Auth owns account state and authorization policy; User owns profile data. The [OpenAPI document](openapi.json) includes the new public endpoints.

## Feature coverage

| Requested capability | Implementation |
| --- | --- |
| Permission-based access | Existing action grants extended with `users:read`, `users:update`, `tokens:introspect`, `devices:trust`, `history:read`, `keys:manage`, `account:delete`, `account:export`, `tenants:manage`. No new `ROLE_ADMIN` shortcuts. |
| Admin user management | Search accounts, filter locks, lock/unlock and deactivate/reactivate. Existing role-assignment APIs remain. |
| Session/token introspection | Owner-only JWT signature/expiry/live-state checks and read-only refresh-ledger/Redis checks. |
| Security notifications | Existing password-change/reset and role/account notices retained; first observation of a device adds a durable new-device email. |
| Account deletion | Reauthentication, immediate revocation, durable cross-service erasure job, retries and admin-visible completion status. |
| Trusted devices | Owner reauthentication, trust expiry up to 90 days, trust removal with device-session revocation. |
| Authentication history | Durable success/failure records, owner-only pagination, outcome/time filtering, 30-day retention. |
| API keys / machine access | Named owner-bound credentials, scopes, expiry, one-time secret disclosure, short-lived machine JWTs and immediate revocation. |
| Fine-grained authorization | Action grants plus subject ownership; cross-user profile access additionally requires an explicit shared tenant. |
| Personal data export | Reauthenticated JSON export of identity, profile, sessions, devices, key metadata, memberships and retained authentication history. |

## Endpoints

All paths below are relative to `/api/v1`. JWT endpoints use `Authorization: Bearer <access-token>`. Errors retain the common API envelope. Protected responses use Spring Security's no-store cache policy. Sensitive mutations accept `currentPassword` and apply the existing account lockout protection.

| Method/path | Grant | Request / behavior |
| --- | --- | --- |
| `GET /auth/users?q=&locked=&active=&status=&sort=email,asc&page=0&size=20` | `users:read` | Pagination, email search, status/lock/activity filters and whitelisted sorting. Excludes deletion tombstones. |
| `PATCH /auth/users/{id}/status` | `users:update` | `{status:"ENABLED"/"DISABLED"/"SUSPENDED",currentPassword}`. Revokes sessions, API-key generations and pending lifecycle proofs. |
| `PUT /auth/users/{id}/roles` | `roles:manage` | Existing `{roles,currentPassword}` assignment API. |
| `GET /auth/roles` | `roles:manage` | Role names and their permissions. |
| `POST /auth/roles` | `roles:manage` | `{name,permissions,currentPassword}`. |
| `PUT /auth/roles/{name}/permissions` | `roles:manage` | Replace permissions; role identifier is its name (e.g. `USER`). |
| `POST /auth/reauthenticate` | authenticated | `{currentPassword}`; issues a proof for GET export, valid for 300 seconds. |
| `GET /auth/session/current` | `sessions:read` | Return only the session identified by the validated JWT `sid`. |
| `GET /auth/users/{id}/deletion` | `users:read` | Erasure state, attempts and timestamps; 404 if no request exists. |
| `POST /auth/introspect` | `tokens:introspect` | `{token}`. Returns `{active:false}` for invalid, expired, revoked or another user's token. |
| `GET /auth/login-history` | `history:read` | `from`, `to` ISO instants; optional `successful`; page/size. Owner derived from JWT. |
| `POST /auth/devices/{id}/trust` | `devices:trust` | `{days:30,currentPassword}`; days 1–90. |
| `DELETE /auth/devices/{id}/trust` | `devices:trust` | `{currentPassword}`; clears trust and revokes owned sessions for that device. |
| `GET /auth/api-keys` | `keys:manage` | Metadata only; never returns secret/hash. |
| `POST /auth/api-keys` | `keys:manage` | `{name,scopes,expiresAt,currentPassword}`; returns `{key,secret}` exactly once. |
| `DELETE /auth/api-keys/{id}` | `keys:manage` | Owner-only revocation, including already-issued machine JWTs. |
| `POST /auth/service-tokens` | API key | `X-Api-Key: hap_…`; no JWT or password in this exchange. Returns access token, Bearer type, TTL and effective scopes. |
| `GET /users/me/export` | `account:export` | Requires `X-Reauthentication-Token` from password reauthentication. Downstream outage returns 503 rather than a partial export. |
| `DELETE /users/me` | `account:delete` | `{currentPassword}`; HTTP 202 and `data.state=PENDING`. Immediately invalidates access. |
| `GET /auth/tenants` | authenticated | Lists only the caller's memberships. |
| `POST /auth/tenants` | `tenants:manage` | `{name,currentPassword}`; creator becomes owner/member. |
| `PUT /auth/tenants/{tenant}/members/{target}` | `tenants:manage` | `{currentPassword}`; only the tenant owner can add members. |
| `DELETE /auth/tenants/{tenant}/members/{target}` | `tenants:manage` | `{currentPassword}`; only the tenant owner; cannot remove its own membership. |
| `DELETE /auth/tenants/{id}` | `tenants:manage` | `{currentPassword}`; only the tenant owner. Removes memberships. |
| `GET /users/{id}?tenantId=…` | contextual | Owner needs `profile:read`; cross-user access needs `users:read` and both memberships. |
| `PATCH /users/{id}?tenantId=…` | contextual | Owner needs `profile:write`; cross-user access needs `users:update` and both memberships. Existing profile-field validation applies. |

Canonical administration paths use `/auth`, never `/admin`. Earlier clients can still use the deprecated `PUT /auth/users/{id}/status` with `{locked,active,currentPassword}`, `/auth/authentication-history`, `POST /auth/export` and `DELETE /auth/account`; new integrations should use the table above. These aliases retain their existing password/permission checks.

`status` is `ENABLED` (active/unlocked), `DISABLED` (inactive) or `SUSPENDED` (active/administratively locked). Sort is `field,direction`, with `email`, `id`, `active`, `locked`, `emailVerified` and `asc`/`desc`; unrecognized properties/directions are rejected. Stable UUID ordering breaks ties. Conflicting status/activity filters return 400.

Search/history page must be 0–10000; size 1–100. History defaults to the last 30 days. `from > to` is rejected. Administrative search/status are platform-level operations; tenant membership does not grant platform administration.

Migration V6 grants the six new self-service permissions to USER and ADMIN; it grants user administration and tenant management to ADMIN. Existing custom roles gain no permissions automatically. Custom policies can grant these individual actions without assigning ADMIN. The last active manager guard includes administrative locks and prevents deleting, locking, deactivating or demoting the last manager. Unlocking does not restore old credentials; the user must log in again. The operator bootstrap script also excludes locked/deleted accounts.

## Machine credentials

A named API key represents a service process operating on behalf of one owning account. It is not an independent human account and has no refresh token or password. Generate it from a normal owner session, then store the one-time secret in the service's secret store. Exchange it from the service for a JWT lasting at most five minutes and never past key expiry.

Allowed scopes are `profile:read`, `profile:write`, `users:read`, `users:update`. Creation requires a nonempty subset of the owner's current permissions, expiry within 365 days and fewer than 20 active keys. Only a SHA-256 digest of the random 256-bit secret is stored. The secret, passwords, token contents and digests are excluded from lists, exports and application DTO logging.

Every Auth/Gateway/User request still validates live state. Effective machine grants are the intersection of the key scopes and the owner's current permissions, with no role authorities. Revoking a key, changing the owner's credential revision, logout-all/session-generation change, account lock, deactivation, deletion or expiry denies subsequent requests. Sensitive account/policy APIs are outside the scope catalog. An API key is never sent as a query parameter.

## Ownership and tenant policy

P2's personal profile remains a single global record keyed by Auth subject. Tenants add access relationships around these records; this change does not create a separate copy of each profile per tenant. No tenant ID from a header or JWT claim grants access by itself.

For cross-user profile operations, User calls Auth's private `/internal/identity/authorize-profile` with the cryptographically validated identity, target UUID, explicit tenant UUID and action. Auth checks live identity/scopes and both SQL memberships. Missing membership, missing action grant or missing tenant denies access. The target account must be active and not locked/deleted. User repeats this policy even when called directly, and fails closed on malformed responses, timeout or Auth outage. Removing membership or permission affects subsequent checks. Already authorized in-flight requests are not canceled across services.

The tenant owner must still possess `tenants:manage`. That grant is for trusted administrators; this implementation does not provide untrusted public tenant invitations or automatic self-join. Remove owned tenants before requesting account deletion; deletion returns 409 otherwise. A tenant removal deletes access relationships, not global user profiles.

## Devices, notifications and history

The existing caller-generated device UUID and User-Agent remain informational. Trust is an owner-confirmed preference with an expiry, not device-bound cryptographic authentication. It never skips password verification, JWT checks, live policy, rate limiting or lockout. Clearing trust revokes the device's current sessions; a future password-authenticated login can register it again.

A first device observation during successful login commits `new-device-login` through the encrypted mail outbox. Refresh or another login with an existing device ID does not send another new-device notice. Failed/rolled-back session creation does not commit the email job. Password-change/reset notifications continue using their existing templates. Mail includes both HTML/text and the managed signature; the new-device notice does not expose raw IP or User-Agent.

Known-account login failures are persisted in a separate transaction so login rollback cannot erase history; success is written in the same transaction as login. Entries contain outcome, reason, timestamp, verified peer/proxy IP and sanitized User-Agent. Unknown-account failures have no owner and are not disclosed to other users. IP/device history is sensitive owner-only data and is purged after 30 days. History storage failure fails the login instead of silently dropping the record.

## Export and controlled erasure

`POST /auth/reauthenticate` requires the current password and a live authenticated JWT. It returns `data.reauthenticationToken`, `expiresAt` and `expiresIn=300`. Send that proof in `X-Reauthentication-Token` for `GET /users/me/export`. Proofs are random, hashed at rest, expire after five minutes and are bound to the authenticated user, session ID, credential revision and session generation. Issuing a new proof replaces the previous proof for that session. A proof does not authorize another user/session or bypass live JWT checks or `account:export`; it is not accepted instead of the password for status changes, deletion or other sensitive mutations. Never put a password or proof in the URL.

Gateway routes **GET `/users/me/export`** and **DELETE `/users/me`** to Auth before the general User route and checks `account:export`/`account:delete`. GET/PATCH `/users/me` still route to User and require profile permissions. Auth exposes the same account endpoints directly. The standalone User service does not implement account export/deletion. Approved CORS origins may send the proof header.

Auth calls User's private service-key-protected profile API at `USER_URL` (default `http://127.0.0.1:8702`) for export/erasure. Use private TLS outside loopback. Gateway has no route to either service's `/internal/**` endpoints. The internal key is `IDENTITY_SERVICE_KEY`, shared with existing identity checks.

Export includes key metadata and retained authentication history but excludes passwords/hashes, OTP/reset proofs, access/refresh tokens, API-key secrets/digests, encrypted mail payloads and other users' profile data. Its DTO redacts `toString()` to keep profile contents out of Spring debug logs. The response is a snapshot across services rather than a distributed transactional snapshot.

Deletion first checks the current password and last-manager/tenant-owner guards, disables the account, invalidates proofs and credentials and writes `account_deletions` in the same SQL transaction. A worker leases a job for 120 seconds, requests User erasure, then scrubs Auth identity and deletes roles, sessions, refresh history, devices, keys, memberships and authentication history. Pending matching recovery/mail jobs are canceled and their encrypted payloads cleared. Already submitted/in-flight SMTP mail cannot be recalled; sent-receipt metadata and earlier encrypted backups are not retroactively erased.

User scrubs profile fields and retains a UUID/version/deleted-marker tombstone to reject late writes and prevent profile resurrection. Auth retains an inactive UUID tombstone with an unusable password marker and synthetic email, job timestamps/status and existing append-only security audit records. These retained identifiers are deliberate operational/audit metadata, not a claim of deletion from all backups or external providers. No self-service restore of a deleted account is supported.

If User is unavailable or local erasure fails, the job remains pending and retries after 60 seconds, without expiring or re-enabling the account. SQL rollback leaves it retryable, including when the remote erase already committed. Failures emit `ACCOUNT_DELETION_FAILURE`; administrators can inspect state/attempts through the status endpoint. Workers use `FOR UPDATE SKIP LOCKED`; User erasure is idempotent. Do not disable outbox workers in production: `app.outbox.worker-enabled=false` also disables scheduled erasure processing for tests.

## Rollout and verification

Auth migrations **V6/V7** and User migration **V2** are additive. V7 stores expiring reauthentication-proof hashes; account statuses reuse the existing active/locked columns. Existing data is preserved; existing device records begin untrusted. Deploy Auth/User/Gateway/Mail together so the expanded policy, internal profile endpoints and new-device template are available. Keep `USER_URL` reachable from Auth and retain the outbox encryption key. No production database or running Compose volume is migrated merely by editing this repository.

```bash
mvn clean verify
python3 scripts/verification/check_coverage.py
python3 scripts/verification/hardening_drill.py
```

`AccessFeaturesHttpTest`, `AuthSecurityIT`, User's profile/internal-erasure tests and `ProfileAuthorizationClientTest` exercise allowed/denied cases, reauthentication, owner isolation, expiry, token-generation invalidation, deletion retries and fail-closed behavior. The full-service drill also verifies actual Gateway/Auth/User/Mail behavior with two Auth instances, scoped PostgreSQL roles and disposable Redis/SMTP.

Design references: [OWASP authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) and [REST API security](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html).

### Recorded verification — 2026-10-30

The full reactor `mvn verify` passed, including 217 Java tests with zero failures, errors or skips, and 93.73% aggregate line coverage. A subsequent targeted run of all 13 account-access HTTP tests passed after adding the live machine-permission-removal assertion.

The isolated full-service drill passed with real PostgreSQL/Redis, two Auth instances and Mail/User/Gateway JVMs. It verified scoped machine-token access and revocation, introspection, history, tenant membership enforcement on direct User calls, admin lock/unlock with stale-JWT denial, trusted devices, complete export and completed cross-service erasure. Existing restart/replay/outage/database-grant checks also passed; the local 80-request/concurrency-eight sample had zero errors. SMTP was a local sink; no external email was sent. The deployment database was not migrated during this verification.

### API contract correction — 2026-10-30

Canonical paths/methods now match the management API list, including PATCH status, login-history, current session, GET self export and DELETE self account. Role IDs remain the existing role-name primary keys. The reactor passed 223 Java tests with zero failures/errors/skips; aggregate line coverage was 93.76%. Tests explicitly cover sort whitelists, status filtering, password requirements, proof expiry and user/session binding, correct Gateway routing and denial when a token has profile permissions without account permissions.

The corrected-path full-service drill also passed: PATCH status, `/auth/login-history`, `/auth/session/current`, password reauthentication followed by GET `/users/me/export` with the bound proof, and password-protected DELETE `/users/me` all worked through Gateway against real services. Existing profile GET/PATCH and live permission checks remained functional. No external email was sent; all databases and SMTP used by the drill were disposable.
