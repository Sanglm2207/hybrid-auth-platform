# P0–P2: reliability and operations

This extension addresses the six gaps found during the P0/P1/P2 review. API prefixes remain `/api/v1`. Auth migration V5 adds durable sessions, refresh replay history, the admin guard, encrypted outbox and audit records. Mail has its own V1 receipt migration in `maildb`; User retains its own V1 profile schema in `userdb`.

## 1. Durable email delivery

Auth commits encrypted mail jobs in `auth_outbox` in the same transaction as the account/proof mutation. Security notices are enqueued **before commit**. SMTP unavailability does not undo a committed account update. Enqueue/storage failure rolls it back. Forgot-password persists a recovery job before account lookup and still returns the same generic response for unknown accounts.

Each Auth instance polls once per second, claiming up to 20 jobs per tick with `FOR UPDATE SKIP LOCKED`. A 120-second lease allows crash recovery; attempt fencing stops an expired worker from completing a newer lease. Exponential retry is capped at five minutes, 12 attempts, and the job's absolute expiry. Verification jobs expire after five minutes, reset/new-email proofs after 15 minutes and security notices after 24 hours. Proof validity is never extended by retries. Finished payloads are erased immediately; hourly cleanup erases expired pending/failed payloads and deletes completed job metadata after 30 days.

Payloads use AES-256-GCM with random nonces and job kind/ID as authenticated data. `prepare-env.sh` generates `MAIL_OUTBOX_ENCRYPTION_KEY`; retain it with encrypted database backups. **Do not replace this key while encrypted jobs remain**: that would make them unreadable. Rotating it requires draining jobs or an explicit decrypt/re-encrypt migration. SQL proof tables continue to store hashes only; the outbox necessarily holds an encrypted delivery copy until delivery/expiry.

Auth sends the stable job UUID as `Idempotency-Key`. Mail HMAC-fingerprints the canonical request with its internal service key (preventing offline OTP guessing from receipt rows), persists a receipt in its own database and skips an already successful matching request. Reusing the ID for different content returns 409. MIME includes the stable Message-ID. SMTP failure leaves no successful receipt, allowing retries.

**SMTP is at-least-once:** a provider can accept mail before the database commit or HTTP response is lost. A crash in that interval can cause duplicate mail; Message-ID is not an exactly-once guarantee. `SENT` means SMTP submission accepted, not delivered to the recipient's inbox. Bounce/complaint webhooks and real-provider inbox placement still require provider-specific integration.

Inspect operational metadata using a migration/operator database account; never select/decrypt payloads in ordinary logs:

```sql
SELECT kind,state,count(*),min(created_at) FROM auth_outbox GROUP BY kind,state;
SELECT id,kind,state,attempts,error_code,expires_at FROM auth_outbox WHERE state='FAILED';
```

After resolving the delivery problem, retry an **unexpired** failed job without changing its ID:

```sql
UPDATE auth_outbox SET state='PENDING',attempts=0,available_at=CURRENT_TIMESTAMP
WHERE id='<job-uuid>' AND state='FAILED' AND expires_at>CURRENT_TIMESTAMP;
```

If a proof expired, request a fresh proof through the normal API. Receipt retention must cover all outstanding retries; no automatic receipt deletion is configured. Drain outstanding jobs before rotating `MAIL_SERVICE_API_KEY`, since receipt fingerprints are bound to that key.

## 2. Revocation survives Redis loss

PostgreSQL `identity_sessions`, `identity_refresh_ledger` and the user's monotonic `session_generation` are authoritative. Every live identity check verifies SQL account state, credential/session generations, session revocation and absolute expiry. Activity is touched at most every 30 seconds. SQL user row locks serialize login/refresh with revocation and credential changes across Auth instances.

Refresh uses both the SQL ledger and atomic Redis rotation. Consumed refresh hashes remain until the family expires. Replay durably revokes the family, including when the denied refresh returns 401. Logout/revoke/all writes SQL in the caller's transaction and does not depend on Redis availability. Redis state cannot restore a revoked SQL session. New login reconciles Redis's generation to the locked SQL value; SQL also enforces the 100 active-session limit.

Redis is still required for login/refresh and abuse controls. Redis loss can invalidate otherwise legitimate refresh tokens and reset rate/lock counters; those users must log in again. Compose enables AOF, `appendfsync always` and `noeviction`. PostgreSQL recovery must preserve session/account history consistently; restoring old SQL backups can also restore old state, so invalidate session generations after disaster recovery if revocation history is uncertain. This is not cross-region consensus.

Deploy Auth, User and Gateway together, then require a new login. Pre-V5 sessions lack a SQL ledger and are rejected. Do not mix old/new Auth binaries under public traffic.

## 3. Last active administrator

A shared SQL guard row is locked before deactivation, role assignment or permission edits. The transaction counts active, email-verified users whose effective permissions include `roles:manage`, flushes the proposed change and rejects it with `409 LAST_ADMINISTRATOR` if it would remove the last manager. Custom manager roles are included. Concurrent changes serialize on the guard, including across instances. Initial operator bootstrap may start with zero managers; the explicit bootstrap script grants one. Direct operator SQL remains outside API safeguards.

## 4. Scoped database users

| Service | Database | Runtime role | Migration/owner role |
| --- | --- | --- | --- |
| Auth | authdb | auth_app | auth_migrator |
| User | userdb | profiles_app | profiles |
| Mail | maildb | mailer_app | mailer_migrator |

Runtime roles have table DML and schema USAGE only: no superuser, database/role creation, schema CREATE or cross-service database CONNECT. Flyway history is inaccessible to them. Auth's runtime role can INSERT/SELECT audit records but cannot UPDATE/DELETE them. Flyway runs with separate credentials and grants runtime access in an `afterMigrate` callback. The Compose-created `auth` superuser is only the local provisioning/operator account; Java runtime does not use it. For stricter production separation, run migrations as a deployment job and avoid giving the long-running process migration secrets.

The setup SQL is idempotent and applies to existing volumes through the runner/VS Code prepare task. It does not reset stored passwords. Configure matching secrets in `.env` and PostgreSQL; set any existing `USER_DB_USERNAME=profiles` override to `profiles_app`. The checked-in passwords are local development defaults and must be replaced for public deployment. Each role must connect only to its owned service database.

## 5. Actor/target audit and collection

Critical account/role mutations insert `security_audit_records` in their SQL transaction. Actor and target are separate; role assignments/policies capture controlled before/after sets; revocation records session/device IDs. A failed audit insert prevents committing the critical mutation. Runtime credentials cannot edit/delete these records. Database owners/operators can: this is append-only for the application, not tamper-proof storage against database administrators.

JSONL events use a strict allowlist for UUIDs and policy fields. Passwords, proofs, raw emails/IPs/profile contents and private keys are excluded. Auth/Gateway/User continue their rolling files. `run-services.sh` starts the local collector by default (`AUDIT_COLLECTOR_ENABLED=true`, port `8710`). VS Code users or monitoring hosts can also start it against a directory containing all service files:

```bash
python3 scripts/audit-collector.py --source logs/security-audit --database logs/audit-collector.sqlite3
curl http://127.0.0.1:8710/metrics
```

It persists cursors and deduplicated events in SQLite WAL, handles file rotation/compression, strips uncontrolled identities and exposes aggregate Prometheus counters/alerts without user identities. It emits `SECURITY_ALERT` for refresh reuse, security-state outages, 30 denied logins/5 minutes or 10 mail failures/5 minutes. The accompanying `infra/observability/prometheus.yml` and `alerts.yml` define scraping and alert rules. Deploy the collector on a protected monitoring host with service log volumes/forwarders, durable storage and backups. Use a separate audit directory per JVM instance and mount these beneath the collector source; collection is recursive, preventing multiple JVMs from rolling the same file. Configure your Prometheus/Alertmanager receiver separately; this change does not send email/Slack messages or deploy a hosted monitoring system. Only expose metrics on a private network. Provision log transport/storage so collector outages cannot exceed source retention.

## 6. Ingress and verification

`GATEWAY_TRUSTED_PROXIES` is an explicit comma-separated list of numeric ingress IPs; empty trusts none. Only a listed TCP peer can supply `X-Forwarded-For`. Gateway walks the chain from right to left and stops at the first untrusted hop, discards malformed chains and strips caller-supplied internal identity headers. It signs the resolved client IP for Auth. Forwarded host/proto never bypass host/origin policy. Configure the actual ingress addresses and make the ingress append the real peer to XFF; do not list arbitrary client ranges. Direct untrusted clients are always identified by their TCP peer.

Run with JDK 25 and a working Docker daemon:

```bash
mvn verify
python3 -m unittest discover -s scripts/verification -p 'test_*.py'
python3 scripts/verification/hardening_drill.py
```

The drill creates disposable PostgreSQL/Redis containers on random loopback ports, real Mail/Auth/User/Gateway JVMs, two Auth instances sharing SQL/Redis, and a loopback-only SMTP sink. It verifies SMTP retry, independent database roles, last-admin protection, concurrent refresh replay, key staging/activation with old/new JWTs, Redis AOF restart/complete data loss, session revocation, identity outage/recovery and 80 authorized requests at concurrency eight. It prints p50/p95 and errors, and deletes its containers on exit. It never flushes Compose Redis or sends external email. Local measurements are a regression baseline; production load/HA/network-partition drills and actual-provider delivery checks must run in the target environment before public rollout.

### Recorded local verification — 2026-10-30

The reactor verification and subsequent affected-module checks passed: 182 Java tests, zero failures/errors/skips. Collector unit verification and an actual loopback `/health`/`/metrics` incident-alert check passed. The isolated PostgreSQL/Redis/SMTP/two-Auth drill passed, including forcing session activity older than 30 seconds (to exercise PostgreSQL transaction write rules) and checking access after Auth restart. The concurrent 80-request/concurrency-eight sample had zero errors, p50 58.65 ms and p95 78.69 ms. These measurements describe one local run and are not a public deployment SLA. No external email or alert notification was sent.
