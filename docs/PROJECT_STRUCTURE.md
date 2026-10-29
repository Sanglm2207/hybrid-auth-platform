# Java package layout

Each module keeps its source under `src/main/java` and tests under `src/test/java`. Service application classes stay in the base package so Spring scans all service subpackages.

```text
auth-service / dev.kaidev.auth
├── AuthApplication.java
├── identity/           Roles/permissions, sessions/devices, state checks and deactivation
├── client/             Internal HTTP client for Mail
├── config/             Spring and security configuration
├── constant/           Auth status codes and public messages
├── controller/         HTTP endpoints
├── dto/
│   ├── request/        Input forms and validation
│   └── response/       Typed response payloads
├── entity/             JPA entities
├── repository/         Database access
├── security/           Redis state/scripts, rate filter, lockout, JWT key ring
└── service/            Login, OTP, account lifecycle/recovery, notices, and sessions

mail-service / dev.kaidev.mail
├── MailApplication.java
├── config/             SMTP/template properties and internal API-key security
├── constant/           Mail status codes and public messages
├── controller/         Internal send, template list, and preview APIs
├── dto/                Validated send/preview inputs and template responses
└── service/            Template loading/rendering and SMTP delivery
    Resources: src/main/resources/templates/email/ (HTML + text alternatives)

user-service / dev.kaidev.user
├── UserApplication.java
├── entity/             User-owned profile entity
├── repository/         Profile database access
├── service/            Profile read/partial update/versioning
├── security/           Auth identity-check client/filter
├── config/             JWT/security configuration
├── controller/         Profile endpoints
└── dto/response/       Profile response payloads

api-gateway / dev.kaidev.gateway
├── GatewayApplication.java
├── config/
│   └── properties/     Typed host/origin settings
└── filter/             Host/origin/CORS enforcement and signed client identity

api-common / dev.kaidev.common
├── api/
│   ├── ApiPaths.java   Versioned API roots
│   ├── code/           Shared status/message catalog
│   └── response/       Response envelope and field errors
├── exception/          Reusable business exception
├── logging/            Structured application log helpers
├── security/           Safe JSON audit events and signed client identity helpers
├── trace/              Request ID handling
├── util/               Normalization helpers
└── validation/
    ├── annotation/     Reusable validation annotations
    └── validator/      Constraint implementations

api-servlet / dev.kaidev.common.servlet
├── config/             Boot auto-configuration
├── controller/         Fallback error endpoint
├── exception/          MVC exception handler
├── filter/             Request tracing
├── security/           Authentication/authorization error writers
└── support/            Response helpers

api-reactive / dev.kaidev.common.reactive
├── config/             Boot auto-configuration
├── exception/          WebFlux exception handler
├── filter/             Request tracing
├── security/           Authentication/authorization error writers
└── support/            Response helpers
```

Unit tests live in the package of the tested controller/service/filter. HTTP contract tests live in each service's `integration` package. The auto-configuration registrations in `META-INF/spring` point to the shared modules' `config` packages.

Add folders when they have code to contain; services do not need empty `repository`, `entity`, or `service` folders.

Auth Lua scripts live in `auth-service/src/main/resources/redis/`. `scripts/jwt-keys.py` and `scripts/GenerateRsaJwk.java` manage private key manifests; `prepare-jwt.sh` imports the existing key for local hot reload. See [P0 security hardening](SECURITY_P0.md).

P1 lifecycle tokens use `AccountActionToken`, `AccountActionTokenRepository`, and the `V3__account_lifecycle.sql` migration. `outbox/` supplies encrypted durable recovery/mail jobs and leased retry workers; account notifications are enqueued before SQL commit. See [Account lifecycle](ACCOUNT_LIFECYCLE_P1.md).

P2 keeps Auth V1–V5 migrations in `auth-service`, and independent profile V1 in `user-service`. `infra/postgres/init-user-db.sql` provisions the local User database; `scripts/grant-admin.sh` is an explicit operator bootstrap. See [Session and identity management](SESSION_IDENTITY_P2.md).

`hardening/` contains SQL session/replay ledgers, the last-administrator guard, transactional audit storage and retention. Mail owns its V1 delivery receipts in `maildb`; scoped Flyway callbacks grant each runtime role only service table access. `scripts/audit-collector.py` merges audit files; `scripts/verification/` contains isolated failure/load/SMTP drills. See [six reliability fixes](HARDENING_RELIABILITY.md).
