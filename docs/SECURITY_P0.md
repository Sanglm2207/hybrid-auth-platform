# P0 security hardening

The Auth service now shares its security state through Redis across instances. Access JWT validation remains local and stateless in Gateway, Auth, and User. This implementation covers atomic refresh rotation/reuse detection, logout-all, IP rate limits, temporary account lockout, JWT key rotation, and structured security audit logs.

## Session lifecycle

Each login creates a family with a **seven-day absolute lifetime**. Refresh tokens remain opaque 32-byte random values (43 base64url characters); Redis keys contain SHA-256 hashes, never raw tokens. Rotation does not extend the family's expiry.

Auth signs the next access JWT before changing refresh state. A Lua script then atomically checks the old token, the family's current hash, expiry, and the user's session generation; records the successor; and replaces the family's current hash. Old token records remain until the absolute family expiry so replay can be recognized.

If a previously consumed token is presented again, the script revokes the entire family, including its current descendant, and emits `REFRESH_REUSE`. Parallel refreshes of one token therefore yield at most one successful response; another concurrent attempt can immediately revoke that winner's refresh session. Clients must serialize refresh requests across tabs/processes and must not blindly retry an uncertain refresh response. Other device families stay active.

`POST /api/v1/auth/logout` accepts a refresh token and idempotently revokes its family. A retained, already-consumed token can also revoke that family's current descendant. Unknown or expired tokens still receive the normal logout response.

### Logout all devices

```http
POST /api/v1/auth/logout-all
Authorization: Bearer <access-token>
```

No JSON body is required, and request data cannot choose which user is logged out. Auth derives the user ID from the verified JWT subject and atomically increments that user's Redis session generation. Every existing refresh family carries its issuing generation; stale generations can no longer rotate. New logins use the new generation. A rotation racing with logout-all cannot recreate a usable old-generation session.

Success returns HTTP 200, code `ALL_DEVICES_LOGGED_OUT`, and `data: null`. Missing/invalid access JWTs return HTTP 401 at both Gateway and Auth.

**Access JWTs already issued remain valid for up to 15 minutes, plus configured validator clock skew.** Logout, logout-all, and refresh replay revoke future refreshes. Immediate access-token revocation is not included: it requires a state check, denylist, or introspection on protected requests.

### Redis layout and rollout

The default namespace is `security:{auth}:`. All script keys use the same Redis Cluster hash tag; every accessed key is supplied explicitly to the Lua script. This provides atomicity on one primary/hash slot, not cross-region linearizability or unlimited horizontal Redis throughput.

| Key suffix | Value | Retention |
| --- | --- | --- |
| `token:<sha256>` | User ID, family ID, issuing generation | Until absolute family expiry |
| `family:<uuid>` | Current token hash or `revoked` | Until absolute family expiry |
| `user-version:<uuid>` | Session generation | Persistent; do not expire independently of sessions |
| `rate:<group>:<ip-hash>` | Fixed-window request counter | Rate window |
| `failures:<email-hash>` | Incorrect password counter | Observation window |
| `lock:<email-hash>` | Temporary lock flag | Lock duration |

Redis failures return HTTP 503 (`SECURITY_UNAVAILABLE`) and deny the operation; there is no per-instance memory fallback. Connection and command timeouts default to two seconds. Use a private, authenticated Redis deployment with persistence, backups, and a `noeviction` policy for security state. Lua atomicity does not prevent state loss during Redis data loss or asynchronous-replication failover. Losing a user's generation while retaining its old token records can undo logout-all, so restore/version state consistently or invalidate the entire session namespace after recovery.

Legacy `refresh:*` / `family:*` records are not accepted by the new implementation. Rolling out this change requires users to log in again. Do not run old and new Auth binaries against public traffic simultaneously: old binaries do not enforce the new policies. Expired legacy keys can age out naturally; the application does not flush Redis.

## Rate limiting and temporary lockout

Limits are enforced in Auth before POST handlers, covering requests through Gateway and direct backend requests. Redis counters are atomic and shared across Auth instances.

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `LOGIN_IP_LIMIT` | 20 | Login POST requests per client IP per window |
| `AUTH_IP_LIMIT` | 60 | Other Auth POST requests per client IP per window |
| `AUTH_RATE_WINDOW_SECONDS` | 60 | Fixed-window duration |
| `LOGIN_FAILURE_THRESHOLD` | 5 | Incorrect passwords before temporary lock |
| `LOGIN_OBSERVATION_SECONDS` | 900 | Window for counting incorrect passwords |
| `LOGIN_LOCK_SECONDS` | 300 | Temporary lock duration, maximum allowed 3600 seconds |
| `AUTH_PROXY_KEY` | Generated by `prepare-env.sh` | At least 32 characters; shared by Gateway and Auth |

Rate limits use a fixed window beginning with its first request; a short burst is possible around a window boundary. Throttled requests return HTTP 429 with `RATE_LIMITED` and `Retry-After` in seconds. Paths are decoded for login classification; encoded aliases and unknown POST paths still pass through rate limiting.

Account lockout is keyed by normalized email across all client IPs. Known and unknown accounts use the same counters and response codes; unknown accounts still perform a BCrypt comparison against a dummy hash. A lock returns HTTP 429, `ACCOUNT_TEMPORARILY_LOCKED`, and `Retry-After`. Attempts while locked do not extend the lock, and an in-flight correct-password attempt rechecks the lock atomically before issuing a session. After expiry, a new observation period begins. Successful password checks clear the incorrect-attempt counter. This is a login lockout; it does not revoke existing sessions or disable email verification. P1 recovery can reset a password and clear the temporary lock after a valid inbox proof; see [account lifecycle](ACCOUNT_LIFECYCLE_P1.md).

### Trusted client identity

Auth ignores arbitrary `Forwarded` / `X-Forwarded-For` headers. Gateway removes caller-supplied `X-Auth-Client-*` headers, then signs its actual TCP peer IP, request timestamp, HTTP method, and raw path using HMAC-SHA256 and `AUTH_PROXY_KEY`. Auth uses that IP only for a valid, fresh signature with exactly one of each header. Unsigned, expired, duplicate, or invalid proofs fall back to Auth's actual peer address.

Gateway refuses to proxy Auth paths when its shared key is missing/too short. Auth still rate-limits direct requests by their peer address. Keep Auth private and use TLS for nonlocal service traffic: a stolen internal identity proof can be replayed within its short validity window. With another reverse proxy before Gateway, the default bucket is that proxy's peer IP, so clients may share a bucket; configure ingress deliberately rather than trusting public forwarding headers. Do not expose Auth directly as a way around deployment ingress controls.

## JWT key rotation

`prepare-jwt.sh` initializes `keys/jwt-key-set.json` from the existing PKCS8 private PEM, preserving its `local-1` kid and key material, and sets `JWT_KEY_SET` in `.env` when unset. Both the terminal runner and VS Code prepare task call it. Keys remain excluded from Git. The Java key generator and Python manifest tool require JDK 25 and Python 3; manifest writes use a mode-0600 temporary file and atomic replacement.

Auth polls the configured private JWK manifest every five seconds. The manifest identifies `activeKid` and contains public verification keys plus private material for the active signer. Only public RSA parameters are returned by `/.well-known/jwks.json`; custom manifest metadata is not copied into that response. JWTs use RS256 and the active kid. A single validated snapshot supplies the header and signing key, so concurrent reloads cannot mix them.

Invalid, missing, duplicate-kid, mismatched-key, or otherwise unsafe reloads leave the last good snapshot active and produce a failed `JWT_KEYS_RELOADED` event. An invalid initial manifest fails startup. A kid cannot change public material during a process's lifetime. Issued keys cannot be removed from that instance's snapshot before their JWT expiry plus 60 seconds of skew. This local guard complements the operational overlap period; it is not a durable record of every token issued by every instance.

### Rotation procedure

After the initial setup/restart to enable the manifest, subsequent rotations do not need a service restart. Use a new kid every time. Run manifest mutations from a single deployment controller/operator and distribute the same manifest version to all Auth instances using atomic file replacement; the CLI is a local file tool, not a distributed key-management coordinator.

```bash
# Bootstrap normally happens through local: prepare / run-services.sh.
bash ./prepare-env.sh
bash ./prepare-jwt.sh

# 1. Publish a new verification key while the previous key still signs.
python3 scripts/jwt-keys.py stage --kid rsa-2026-11
python3 scripts/jwt-keys.py list

# 2. Verify every Auth instance publishes both kids at its public JWKS endpoint.
# Allow the deployment's JWKS cache propagation interval before switching signers.
python3 scripts/jwt-keys.py activate --kid rsa-2026-11

# 3. Verify every Auth instance now issues tokens with the new kid.
# Keep the old key for at least 17 minutes AFTER the last instance switches,
# and longer if your access TTL, clock skew, or deployment propagation requires it.
python3 scripts/jwt-keys.py retire --kid local-1
```

The CLI refuses to retire an active key, retire a previously active key within 17 minutes of its activation switch, or reuse a retired kid. It does not know when every remote instance has reloaded: the operator must verify that before starting the retirement wait. A prematurely edited file that the running process rejects is also unsafe to deploy on restart; repair it before restarting any Auth instance.

Gateway and User use remote JWKS decoders and refresh their key sets when encountering a new kid. Keep old public keys published for overlapping token validation. The suite tests an actual Gateway decoder against a changing HTTP JWKS endpoint, as well as Auth's local snapshot reloads.

When `JWT_KEY_SET` is explicitly empty in a manual launch, Auth supports the original PEM files as a compatibility fallback; that mode does not hot-reload keys. No signing keys are rotated automatically on a schedule. For production, store and distribute private material using the deployment's secret controls; this repository provides a local manifest workflow, not a KMS integration.

## Security audit logging

`SecurityAudit` writes JSON events with UTC timestamp, controlled event/outcome names, canonical user UUID (or `anonymous`), and a validated trace ID. Raw emails, IPs, passwords, OTPs, refresh tokens, Authorization headers, provider messages, and private keys are excluded. Successful login, denied login, logout, logout-all, successful/denied refresh, refresh reuse, lockout, rate limiting, key reload, Redis failure, and JWT authentication/authorization failures are recorded at their respective boundaries.

Auth, Gateway, and User write separate JSONL files under `logs/security-audit/` by default. Set `AUDIT_LOG_PATH` to choose another directory. Files rotate daily or at 10 MB, with at most 90 days of history and a 1 GB archive cap; available storage may shorten retention. Audit events also go to the console for an external collector. The directory must be writable only by the service/operator. These are local rolling logs, not an immutable central audit store; configure collection, storage monitoring, permissions, retention, and alerts in deployment.

## Verification

Run `mvn verify` with JDK 25, Python 3 for the setup tools, and a working Docker daemon. The security integration suite creates an isolated `redis:7.4-alpine` container on a random loopback port and removes it afterward. It never flushes or modifies the Compose Redis database.

Coverage includes concurrent rotation across two service instances, replay/family isolation, logout-all/refresh races, expiry, signing failure, atomic rate limits, lock expiry without extension, unknown-account dummy work, in-flight lock checks, signed client identities, encoded paths, fail-closed Redis errors, protected logout-all HTTP contracts, public-only JWKS, invalid reload retention, concurrent signing during rotation, remote JWKS refresh, and redacted JSON audit events.

Design references: [Redis atomic script execution](https://redis.io/docs/latest/develop/programmability/eval-intro/), [OAuth refresh-token replay protection (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2), [OWASP authentication controls](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), and [OWASP security logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
