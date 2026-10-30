# P4 — Automated testing and security verification

P4 adds JUnit 5/Mockito regression tests, Spring Security Test, Testcontainers PostgreSQL/Redis integration tests, an executable OpenAPI core contract, JaCoCo reports and GitHub Actions security gates. The ASVS mapping below records evidence for specific controls; it does not assert full ASVS certification.

## Run locally

Use JDK 25, Maven, Node.js, Python 3 and a working Docker daemon. Integration tests require Docker and fail if it is unavailable; they are never silently skipped.

```bash
mvn clean verify
python3 scripts/verification/check_coverage.py
node --test auth-service/src/test/js/*.test.cjs
python3 -m unittest discover -s scripts/verification -p 'test_*.py'
```

`mvn test` runs unit, HTTP, contract and security-chain tests without Docker. `mvn verify` additionally runs `*IT` through Failsafe. Existing Redis concurrency tests now use the Testcontainers JUnit lifecycle rather than shell-managed Docker containers. `AuthSecurityIT` uses real PostgreSQL/Flyway, Redis Lua, BCrypt, transaction proxies and JWT validation; only the outbound mail client is mocked. Each integration class owns disposable containers on random ports. The PostgreSQL fixture uses its generated database owner and migration-only locations; scoped runtime credentials are verified separately by the full-service drill.

Reports:

- Per module: `target/surefire-reports`, `target/failsafe-reports`, `target/site/jacoco/index.html` and `jacoco.xml`.
- Whole reactor, including shared libraries exercised by service tests: `coverage-report/target/site/jacoco-aggregate/index.html` and `jacoco.xml`.
- Maven line gates: Auth/User/Gateway 70%, Mail 90%, Common 30%. Modules without their own tests contribute through the aggregate report. CI additionally requires 70% aggregate line coverage and fails on missing reports. These initial floors preserve a measurable regression baseline without excluding production packages from measurement.

JaCoCo 0.8.14 supports this repository's JDK 25: [official release history](https://www.jacoco.org/jacoco/trunk/doc/changes.html).

## Mandatory scenarios and evidence

| Scenario | Automated evidence | Expected invariant |
| --- | --- | --- |
| Concurrent refresh | `AuthSecurityIT.concurrentRefreshHasOneWinnerAndReplayRevokesAccessAndDescendant`, `RedisSecurityIT.parallelRotationAcrossInstancesHasOneWinnerAndReuseRevokesWinner`, two-Auth drill | Exactly one rotation succeeds; replay invalidates the winning family. |
| Refresh replay | `AuthSecurityIT.sequentialReplayCommitsRevocationDespiteUnauthorizedResponse`, `DurableSecurityTest` | SQL revocation commits even when replay returns 401; descendants and access fail. |
| Forged / expired JWT | `AuthSecurityIT.rejectsExpiredAndForgedJwtBeforeIdentityLookup`, Gateway/User `JwtRejectionTest` | Invalid signature and expired claims fail at real decoders. Gateway/User also reject unsigned tokens and wrong issuer/audience. |
| Logout all devices | `AuthSecurityIT.logoutAllRejectsBothAccessAndRefreshForEveryDeviceAndPreservesOtherUsers`, Redis race tests | Access and refresh fail on all devices; another user and a fresh login remain usable. |
| IDOR/BOLA | `AuthSecurityIT.anotherUserCannotRevokeAnOwnedSession`, `IdentityHttpTest.deviceHistoryIsOwnedAndDeletingDeviceRevokesItsSessions` | An authenticated user cannot revoke another user's session/device; victim remains authorized. |
| Brute force | `AuthSecurityIT.bruteForceLocksAccountAndCorrectPasswordCannotBypassLock`, Redis atomic rate-limit tests | Repeated failures lock the account, return Retry-After and cannot be bypassed with a correct password. |
| Auth service permissions | `IdentityHttpTest` role/permission/deactivation cases | Live database permissions and ownership govern access; role changes invalidate stale credentials. |
| User service permissions | `ProfileHttpContractTest.livePermissionsAreEnforcedOnTheServiceItself`, `springSecurityTestCannotBypassLivePermissions`, full-service drill | Direct calls enforce read/write permissions independently of Gateway. |
| Gateway permissions | `GatewayIdentityFilterTest`, `GatewayPolicyTest`, full-service drill | Live identity grants drive authorization; identity outages fail closed. |
| Mail service permissions | `MailHttpContractTest` | Missing/wrong internal keys cannot send or preview mail. |

## OpenAPI contracts

`docs/openapi.json` is an OpenAPI 3.0.3 contract for login, refresh, logout, logout-all, profiles and the [account access extension](ACCOUNT_ACCESS.md). `AuthHttpContractTest` and `ProfileHttpContractTest` use Atlassian's validator against real MockMvc responses, checking request/response shapes, required envelope fields and typed data. Existing HTTP tests cover the remaining legacy account/role/mail routes, but those legacy routes are not yet represented in this core OpenAPI document. Keep `docs/API.md`, the spec and its test assertions aligned when changing API behavior.

## CI gates and scanning

`.github/workflows/p4-testing.yml` runs on pushes, pull requests, manual dispatch and a weekly schedule. Jobs have read-only repository permissions and upload reports even on failures.

1. Tests run `clean verify`, aggregate coverage checks, JS tests and Python tests.
2. [Trivy filesystem scanning](https://trivy.dev/docs/latest/target/filesystem/) builds and inventories actual packaged Java dependencies into CycloneDX, then blocks HIGH/CRITICAL vulnerabilities, including those without a fix. It does not use an ignore file or `--ignore-unfixed`. Scan/download failures fail the job. Review the JSON artifact to distinguish an application upgrade from a transitive dependency fix.
3. The isolated drill boots real PostgreSQL, Redis, SMTP sink, Mail, two Auth instances, User and Gateway. It exercises concurrency, direct-service permission enforcement, database grants, restarts and outages. With `P4_ZAP=true`, it also runs authenticated ZAP active scanning against profile GET/PATCH on the disposable User service. Medium/high ZAP alerts fail the job; low/informational alerts stay in the HTML/JSON reports. This scan covers the profile attack surface; the application-level regressions cover auth/admin behavior.

Run the same DAST fixture on Linux or macOS Docker Desktop:

```bash
mvn -DskipTests package
P4_ZAP=true python3 scripts/verification/hardening_drill.py
```

ZAP uses [the official API scan](https://www.zaproxy.org/docs/docker/api-scan/). Its target port and JWT come from the local disposable drill. Credentials are written to a temporary config, excluded from command arguments, redacted from published reports and removed on exit. Reports are under ignored `reports/zap/`. No Compose volumes or external SMTP accounts are used. ZAP and Trivy download images/rule or vulnerability databases, so these jobs require network access. Changing findings can intentionally fail a later scheduled run even when source code is unchanged.

## ASVS 5.0 evidence map

Requirement IDs refer to the [OWASP ASVS 5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en), not ASVS 4.x numbering. These are targeted regression mappings, not a claim that every clause of each requirement has been assessed.

| ASVS requirement | Evidence | Remaining assessment |
| --- | --- | --- |
| 6.3.1 authentication attack controls | HTTP brute-force lockout and atomic Redis rate tests | Production thresholds, distributed abuse and operational recovery. |
| 7.2.1 trusted backend session checks | Auth/User/Gateway live identity checks and outage tests | Deployment topology and every future consumer. |
| 7.4.1 session termination | Logout/replay/generation, SQL restart and Redis-loss tests | In-flight work and target-environment recovery procedures. |
| 8.2.1 function permissions | Auth role management, profile read/write and internal Mail tests | Complete endpoint inventory as APIs grow. |
| 8.2.2 object permissions | Cross-user session/device attacks | New object types and multi-tenant boundaries if introduced. |
| 8.2.3 field permissions | Profile rejects roles/userId and unknown fields | New fields and policy changes. |
| 8.3.1 trusted service authorization | Direct Auth/User tests and full-service drill | Ingress/network isolation in deployment. |
| 9.1.1 token integrity | RSA forgery rejected by real JWT decoders | Key custody and production rotation procedures. |
| 9.1.2 algorithm allowlist | Unsigned JWT rejected at Gateway/User decoders | Full algorithm-confusion/key-type matrix. |
| 9.2.1 token validity | Expired JWT rejected outside allowed clock skew | `nbf`, clock drift and deployment time synchronization. |
| 9.2.3 token audience | Wrong audience rejected at Gateway/User | Future token types and service-specific audiences. |

TLS/ingress configuration, production secrets, MFA, a complete ASVS applicability review and independent penetration testing remain separate deployment work. A passing pipeline demonstrates the listed regressions, coverage and configured scanner thresholds only.

## Verification recorded — 2026-10-30

`mvn verify` passed with 200 Java tests, zero failures/errors/skips. The 19 Docker integration cases comprise 13 Redis tests and 6 PostgreSQL/Redis HTTP security tests. The aggregate line gate passed at 93.66% (1462/1561 lines), with no production package exclusions. The six Node.js account-action tests and the Python audit-collector test also passed.

The newly added Trivy and ZAP execution paths remain unverified locally: automatic approval review rejected mounting application JARs into the Trivy image and supplying a disposable authenticated JWT to the ZAP image, citing exposure to third-party container code. Their CI configuration and local runner are present, but no clean vulnerability/DAST result is claimed. Execution requires explicit approval for those scanner inputs. The existing full-service drill was not rerun as part of the rejected combined ZAP command.
