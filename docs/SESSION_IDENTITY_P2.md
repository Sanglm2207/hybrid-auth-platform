# P2 session and identity management

The [account access extension](ACCOUNT_ACCESS.md) adds Auth V6–V7/User V2 migrations, action permissions, admin account status, introspection, trusted devices, history, machine credentials, tenant profile policy, export and a separate deletion workflow. Its current rules supersede the earlier limitations below.

P2 adds active-session/device management, persisted roles and permissions, a separate User-owned profile database, and account deactivation. Auth owns identity/credentials/security state; User owns profile data. Neither service queries the other's database. The local PostgreSQL instance hosts two databases with different service credentials.

## API

All endpoints require a valid access JWT and a current account/session state. Paths are versioned under `/api/v1`.

| Method and path | Permission | Behavior |
| --- | --- | --- |
| `GET /auth/sessions` | `sessions:read` | List the caller's active refresh families |
| `DELETE /auth/sessions/{id}` | `sessions:revoke` | Revoke one owned session family |
| `GET /auth/devices` | `devices:read` | List owned device history and active-session counts |
| `DELETE /auth/devices/{id}` | `devices:revoke` | Revoke that device's owned sessions and remove its device record |
| `GET /auth/roles` | `roles:manage` | List role definitions and permissions |
| `GET /auth/permissions` | `roles:manage` | List the supported permission catalog |
| `POST /auth/roles` | `roles:manage` | Create a named role |
| `PUT /auth/roles/{name}/permissions` | `roles:manage` | Replace that role's permissions |
| `PUT /auth/users/{id}/roles` | `roles:manage` | Replace a user's role assignments and invalidate their sessions |
| `GET /users/me` | `profile:read` | Return the caller's persisted profile or defaults |
| `PATCH /users/me` | `profile:write` | Update allowed fields in the caller's own profile |
| `POST /auth/deactivate` | `account:deactivate` | Verify current password and disable the caller's account |

Revocation returns HTTP 200 with `SESSION_REVOKED` or `DEVICE_REVOKED`. Unknown/unowned session or device IDs return HTTP 404 without disclosing another user's resources. Permissions grant operations, not cross-user ownership: even ADMIN's session/device endpoints act on its own subject.

## Sessions and devices

A session ID is the JWT's `sid` and identifies one refresh family. Responses include `id`, `deviceId`, `userAgent`, `ip`, `createdAt`, `lastActivityAt`, `expiresAt`, and `current`. No token or token hash is returned. Lists are ordered by recent activity and bounded to 100 active sessions per user; excess login attempts receive HTTP 429 `SESSION_LIMIT_REACHED`. Rotation and reuse detection retain their existing atomic Lua behavior.

Optionally send `X-Device-Id: <UUID>` when logging in. A client may persist this identifier to group multiple sessions under one device; if omitted, Auth generates a fresh device UUID. Refresh retains the original device ID. Device ID and User-Agent are caller-supplied informational metadata, not authentication factors or proof of a physical device. Malformed/duplicate device headers are rejected. User-Agent control characters are stripped and values are limited to 256 characters.

IP comes from the verified Gateway HMAC identity or the actual direct peer address; arbitrary forwarding headers are ignored. Auth persists device observations on login/refresh in `identity_devices`. Active session request activity is updated in Redis when identity state is validated. Device responses merge live session activity with the stored observation and include first-seen time, last IP, current-device flag, and active-session count. Once a session expires or leaves the active index, the durable timestamp represents the last login/refresh observation, not an indefinite history of every request.

Deleting a device removes its durable device row and revokes its currently owned sessions. A later successful login with that device ID can register it again; this is not a hardware ban. Ordinary session logout/revocation retains the device history. Device metadata/IP is sensitive owner-only API data and is not included in the security audit payload.

Session metadata and indexes live in Redis under `security:{auth}:`. Token/family/metadata expiry remains the family's seven-day absolute lifetime. Per-user session indexes are updated atomically on issue/revoke and cleared on logout-all. A persisted last-issuing credential revision clears obsolete index entries after an explicit operator bootstrap. Each Lua script receives all accessed keys in the same cluster hash slot; listing is a bounded read snapshot, so concurrent changes can appear on the next list request.

## Live identity validation and immediate revocation

P2 changes the previous P0/P1 stateless-access policy. Cryptographic JWT validation still happens locally, but **each request carrying an access JWT also validates current identity/session state**:

- Auth checks its own SQL user record and Redis family/generation/credential state.
- Gateway calls Auth's private `POST /internal/identity/check` before route authorization.
- User independently calls the same Auth API, protecting direct backend access as well as Gateway traffic.

The internal request carries the verified subject, session ID, session generation (`sv`), and credential revision (`cv`). Only a caller that has already validated JWT signature, issuer, audience and expiry should construct it. The endpoint is protected by a separate shared `IDENTITY_SERVICE_KEY`, has no Gateway route, and returns no roles/permissions for inactive identities. This is an application-specific state-check contract, not an implementation of the OAuth RFC 7662 wire protocol.

A valid result supplies authoritative roles/permissions from Auth SQL. Callers install these authorities for authorization instead of trusting stale JWT role claims. Removed role permissions take effect on the next check without requiring a new JWT. Role assignment changes increment credential revision and revoke refresh families, so affected users must log in again.

Revoked sessions, logout-all, credential changes and deactivation reject existing access JWTs on subsequent protected requests, even before their cryptographic expiry. Already authorized in-flight requests are not canceled or rolled back across services. Legacy JWTs missing `sid`/`sv`/`cv` and legacy refresh records missing P2 metadata require a new login at rollout.

There is no positive identity-decision cache. A `/users/me` request through Gateway normally performs two Auth state checks, one at Gateway and one at User. This adds network/SQL/Redis cost and makes Auth availability part of protected-request availability. A denied identity returns HTTP 401; missing internal configuration, network/timeout failure, or an invalid remote acknowledgement fails closed with HTTP 503. Remote check timeouts are bounded to three seconds (User's connect timeout is two seconds). Keep the internal endpoint private and use TLS for nonlocal service traffic. Redis consistency/persistence requirements from P0 still apply.

## RBAC

Auth SQL stores `identity_roles`, `identity_role_permissions`, and `identity_user_roles`. The migration preserves existing role assignments; the old scalar `app_users.role` column remains only for compatibility and is no longer authoritative.

Built-in roles:

- `USER`: profile read/write, owned session/device read/revoke, account deactivation.
- `ADMIN`: the USER permissions plus `roles:manage`.

The supported permission catalog is `profile:read`, `profile:write`, `sessions:read`, `sessions:revoke`, `devices:read`, `devices:revoke`, `account:deactivate`, and `roles:manage`. New role names use uppercase letters/digits/underscores, start with a letter, and have at most 32 characters. User assignments contain 1–16 existing roles. Unknown permissions are rejected. The ADMIN definition must retain `roles:manage`; administrators can still remove their own ADMIN assignment or deactivate their account, so maintain an operator recovery path.

Role creation/update requires `name`, `permissions`, and `currentPassword`. The path name and request name must match on update. User-role assignment requires `roles` and the acting administrator's `currentPassword`. Reauthentication uses the shared temporary-lockout policy. Role management is checked both at the controller permission boundary and against the current actor during mutation. User row locks use a stable order for cross-user assignments.

```json
{
  "name": "VIEWER",
  "permissions": ["profile:read", "sessions:read"],
  "currentPassword": "<administrator password>"
}
```

No public bootstrap endpoint or default administrator account is added. To promote an already verified, active account during explicit local operator setup:

```bash
bash scripts/grant-admin.sh administrator@example.com
```

This script uses the operator's Compose database access, grants ADMIN only to an eligible existing account, and increments its credential revision. Old access/refresh credentials are invalidated by the revision checks. Log in again afterward. The script does not run automatically or reactivate disabled accounts. Production promotion/recovery should use the deployment's audited database/operator controls.

Role assignment sends `roles-changed`; deactivation sends `account-deactivated`. Both are signed HTML/text notifications dispatched after SQL commit, with the same best-effort delivery behavior as P1.

## User-owned profile

User's database is `userdb`, using the `profiles` role by default. Its `user_profiles` table uses the immutable Auth subject UUID as an external identifier, with no cross-database foreign key. It stores `displayName`, `bio`, `locale`, `timeZone`, `updatedAt`, and an optimistic `version`. Email, passwords, account status and role policy remain in Auth.

Profiles are created lazily on the first PATCH; GET before that returns empty display name/bio, `en`, `UTC`, and version 0. Response `id` and `roles` remain for compatibility; roles are derived from the validated identity/JWT and are not persisted or editable as profile fields.

```json
{
  "displayName": "Kai",
  "bio": "Building services",
  "locale": "vi-VN",
  "timeZone": "Asia/Ho_Chi_Minh",
  "version": 0
}
```

PATCH updates only non-null supplied fields. Empty display name/bio clears them. Display name is limited to 100 characters, bio to 500, locale to a validated language tag of at most 35, and time zone to a valid Java ZoneId of at most 64. An optional `version` rejects stale writes with HTTP 409. Unknown fields such as `id`, `userId`, `email` or `roles` are rejected. Existing profile updates are row-locked; concurrent first creation can receive a conflict and should be retried after reading the profile.

## Account deactivation

Send `{ "currentPassword": "..." }` with the account's JWT to `/api/v1/auth/deactivate`. Auth marks the account inactive, records deactivation time, increments credential revision, invalidates pending lifecycle tokens, and revokes refresh sessions. Existing JWTs are denied by live identity checks. Login with the correct password returns `ACCOUNT_DISABLED` (HTTP 403); forgot-password remains a generic response but sends no reset mail for an inactive account. Existing reset/email-change proofs cannot reactivate it.

This is deactivation, not hard deletion. Identity, roles, device history and User-owned profile data are retained. No self-service reactivation or data-erasure workflow is included; those require a separate policy/API.

## Local setup and rollout

| Variable | Default / purpose |
| --- | --- |
| `IDENTITY_SERVICE_URL` | `http://127.0.0.1:8701`, used by Gateway/User |
| `IDENTITY_SERVICE_KEY` | Generated by `prepare-env.sh`; shared by Auth/Gateway/User, at least 32 characters |
| `USER_DB_URL` | `jdbc:postgresql://127.0.0.1:5432/userdb` |
| `USER_DB_USERNAME` | `profiles_app` |
| `PROFILE_DB_PASSWORD` | Local default `profiledev` |

`infra/postgres/init-user-db.sql` creates the profile database/role on first PostgreSQL initialization. The terminal runner and VS Code prepare task also run it explicitly for existing volumes; it creates missing objects without resetting existing passwords. Changing a database password in `.env` does not update an existing role's stored password. Java runtime uses scoped `auth_app`, `profiles_app` and `mailer_app` roles. The Compose-created `auth` administrator is for provisioning only.

Auth runs migration V5; User runs its own independent V1 migration. Restart Auth, User, Gateway and Mail with the updated environment. A new login is required for P2 claims/session metadata. CORS now permits GET/POST/PATCH/PUT/DELETE/OPTIONS and the optional `X-Device-Id` header; authorization and ownership still decide which operations succeed.

Audit events include session/device revocation, role/permission changes, profile updates, and account deactivation. Application helpers exclude credentials, token contents and raw device/IP/profile values. Operator bootstrap activity needs separate operational auditing.

Verification covers Redis ownership/revocation, credential-version invalidation, RBAC/method-security failures, account deactivation, profile persistence/field restrictions, live permissions and identity outage handling. See `mvn verify` and the integration tests in Auth, User and Gateway.

Design reference: [OWASP authorization: deny by default and validate every request](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).

The [six reliability fixes](HARDENING_RELIABILITY.md) add authoritative SQL session revocation/replay history, last-active-manager protection, encrypted mail outbox/receipts, scoped database roles, actor/target audit collection and failure/load drills. SQL durability supersedes earlier Redis-only session descriptions above.
