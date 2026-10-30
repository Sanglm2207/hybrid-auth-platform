# P6 — Resilience & Distributed Systems

P6 adds dependency circuit breakers, bounded network/database waits, safe read retries,
jittered durable retries, health probes and explicit graceful shutdown. Existing SQL
outbox and Mail receipt idempotency remain the delivery mechanism.

## Request and delivery policy

| Boundary | Deadline / policy |
| --- | --- |
| Gateway → Auth/User | Connect 2s; pool acquisition 2s; response 15s; max 200 pooled connections. No retry filter and Reactor Netty TCP retry disabled. |
| Gateway → live identity | Overall 3s; no application retry; circuit breaker; deny access on failure. |
| User → identity check / profile authorization | Connect 2s + read 3s per attempt; at most 2 attempts, with 50–100ms jitter. These POST endpoints only read live policy. |
| Auth → profile export | Connect 2s + read 3s per attempt; at most 2 attempts, with 50–100ms jitter. |
| Auth → profile erasure | Connect 2s + read 3s; one HTTP attempt per durable deletion claim. |
| Auth → Mail | Connect 2s + read 20s; one HTTP attempt per durable outbox claim; same delivery UUID on retry. |
| Gateway/User → JWKS | Connect 2s + read 3s; no added application retry. |
| Redis | Connect/command 2s; fail closed; no new application retry layer. |
| PostgreSQL | Pool acquisition 2s, validation 1s; driver connect 2s, socket read 5s; server statement 5s, lock wait 2s; JDBC template query 5s; default transaction 10s. |
| SMTP | Connect/read/write 5s each; retry belongs to the outbox. |

Timeouts bound individual waits; they are not a single wall-clock deadline for an
entire multi-step API transaction. JDBC driver settings are applied before Hikari
initialization to PostgreSQL pools only, including environment-supplied JDBC URLs.
Explicit driver properties or URL options can override these defaults. H2 tests do
not receive PostgreSQL-specific settings.

Circuit breakers use Resilience4j 2.3.0: a 10-call window, minimum 5 calls, 50%
failure threshold, 10s open period, then 2 half-open trial calls. Gateway groups its
Auth, export and deletion routes under one Auth breaker; User routes have a separate
breaker. Private identity, profile and Mail clients each have a local breaker.
Breakers live in each JVM, require no healthy Redis to operate, and never replace a
live permission check with a cached allow decision. HTTP 4xx does not trip a client
breaker; HTTP 5xx and transport failures count. Open circuits return 503 immediately.
The `dependency.circuit.state` gauge is exported through P5 OTLP metrics (Prometheus `dependency_circuit_state`), tagged by dependency: 0 closed, 1 open, 2 half-open.
Safe read retries cover connection errors and 502/503/504 only, and stop after one
retry. They do not retry validation errors, denial, invalid acknowledgements or an
open circuit. No Gateway request is automatically replayed.

## Refresh token: unknown outcome means reauthenticate

`POST /api/v1/auth/refresh` remains a single-use rotation. Neither Gateway nor the
Auth session service adds automatic retries. Gateway 502/504 responses for this
endpoint carry `X-Refresh-Outcome: unknown` and `Cache-Control: no-store`; the header
is exposed to approved browser origins and documented in OpenAPI.

Client rules:

1. Serialize refresh per session, including multiple browser tabs. Replace the old
   refresh token atomically after a successful response.
2. On a timeout, dropped connection or unknown-outcome response, stop automatic
   refresh. The server may already have committed rotation. A client timeout can
   happen before Gateway sends its response, so this rule also applies when no
   response header was received.
3. Reauthenticate through login to obtain a fresh session. If the old access token
   still works, revoke its session with `DELETE /api/v1/auth/sessions/{id}`. Otherwise
   log in first, list sessions and revoke the old session; use logout-all when all
   sessions should be invalidated.
4. Never resubmit the old refresh token to discover whether it worked. A replay
   revokes the affected session family, including the newly rotated token. The
   server deliberately does not return a cached successful refresh response for an
   `Idempotency-Key`.

A 503 caused by an already-open route circuit is rejected before forwarding, but
clients still use the conservative recovery rule whenever they cannot prove the
original request was never processed. Reverse proxies, SDKs and frontend clients
must follow the same no-replay policy.

## Outbox, idempotency and crash recovery

Account changes and encrypted `auth_outbox` insertion commit in the same SQL
transaction. Rollback leaves no mail job. Workers claim with `FOR UPDATE SKIP LOCKED`,
persist a 120s lease and increment attempts. A crashed worker's lease becomes
claimable; completion and retry updates require the current attempt number, so an
old worker cannot overwrite a newer claim.

Mail delivery UUIDs are stable across attempts and sent as `Idempotency-Key` to the
private Mail API. The SQL receipt binds a UUID to a request fingerprint: a completed
duplicate succeeds without another send; a changed payload returns 409. Delivery
is **at least once**: an SMTP acceptance followed by a crash before SQL receipt
commit can still produce a duplicate. A stable Message-ID helps reconciliation;
SMTP does not provide exactly-once delivery.

Outbox retries persist equal-jitter exponential delays (half-cap to cap, up to
300s), stop at 12 attempts or payload expiry, and keep FAILED jobs visible. Profile
deletion uses the same backoff without a finite attempt limit, since erasure must
remain retryable. Its remote tombstone operation is idempotent; retry updates are
fenced by attempt number. Deletion completion remains serialized by the owner row
lock. These operation-specific guarantees do not add generic idempotency to every
public POST endpoint.

## Shutdown and probes

All four services explicitly use graceful shutdown with 30s per shutdown phase.
Scheduled tasks wait up to 30s. Auth workers stop claiming new jobs when the context
closes, finish the current job if possible, and otherwise rely on persisted leases.
Send SIGTERM; allow at least 65s before an orchestrator sends SIGKILL, since the
scheduler and web server can stop in separate phases. Forced termination remains
recoverable through the outbox lease. Unready instances must be removed from the
load balancer before termination.

Public health responses contain status only; Actuator env/config/metrics endpoints
are not added to the exposure allowlist.

| Service | `/actuator/health/liveness` | `/actuator/health/readiness` |
| --- | --- | --- |
| Gateway :8700 | JVM lifecycle | JVM readiness |
| Auth :8701 | JVM lifecycle | JVM readiness + PostgreSQL + Redis |
| User :8702 | JVM lifecycle | JVM readiness + PostgreSQL |
| Mail :8703 | JVM lifecycle | JVM readiness + PostgreSQL |

Liveness excludes dependencies to avoid restart loops during outages. Readiness
returns 503 when its listed dependencies are down. Gateway/User do not put a shared
Auth HTTP outage into readiness; live checks fail closed and breakers isolate it.
Mail deliberately excludes SMTP: a provider outage is handled by durable retries.
These probes report readiness; they do not themselves configure a load balancer.

Import these individual cURL requests into Apidog:

```bash
curl --request GET 'http://localhost:8700/actuator/health/liveness'
```

```bash
curl --request GET 'http://localhost:8701/actuator/health/readiness'
```

```bash
curl --request GET 'http://localhost:8702/actuator/health/readiness'
```

```bash
curl --request GET 'http://localhost:8703/actuator/health/readiness'
```

## Verification

```bash
mvn -B verify
python3 scripts/verification/check_coverage.py
python3 scripts/verification/resilience_drill.py
```

The drill requires packaged JARs, JDK 25 and Docker. It loads no `.env`, generates
test identities/keys, uses isolated PostgreSQL/Redis containers and a loopback SMTP
sink, and cleans up its own resources. It does not pause the application's Compose
containers. Success writes `reports/resilience/result.json`. CI runs this as the
`resilience` job.

- `DependencyGuardTest`: bounded read retry, write never retried, 4xx ignored,
  open/half-open/recovery, independent dependencies, interruption and capped jitter.
- `GatewayResilienceTest`: a simulated committed refresh with a late response
  returns 504; a TCP abort returns 502. Both reach upstream exactly once, even on
  fresh connections. Repeated failures open the route circuit and stop forwarding.
- `DurableSecurityTest`: transaction rollback, encrypted jobs, lease recovery and
  stale completion fencing. Mail HTTP tests cover duplicate delivery and conflicting
  idempotency payloads.
- Real JVM drill: SIGTERM during a pending HTTP request preserves its response;
  paused Redis/PostgreSQL causes bounded readiness failure and rejected login while
  liveness remains UP; dependency recovery restores readiness; stopped User service
  fails with 502 then recovers on restart. Existing drill also checks SMTP recovery,
  concurrent refresh/replay, Auth outage and persistent-session restart.

References: [Reactor Netty retry behavior](https://projectreactor.io/docs/netty/release/reference/http-client.html),
[Resilience4j circuit breaker](https://resilience4j.readme.io/docs/circuitbreaker),
[Spring Boot health probes](https://docs.spring.io/spring-boot/3.5/reference/actuator/endpoints.html).
