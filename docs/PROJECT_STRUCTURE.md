# Java package layout

Each module keeps its source under `src/main/java` and tests under `src/test/java`. Service application classes stay in the base package so Spring scans all service subpackages.

```text
auth-service / dev.kaidev.auth
├── AuthApplication.java
├── config/             Spring and security configuration
├── constant/           Auth status codes and public messages
├── controller/         HTTP endpoints
├── dto/
│   ├── request/        Input forms and validation
│   └── response/       Typed response payloads
├── entity/             JPA entities
├── repository/         Database access
└── service/            OTP and token/session logic

user-service / dev.kaidev.user
├── UserApplication.java
├── config/             JWT/security configuration
├── controller/         Profile endpoints
└── dto/response/       Profile response payloads

api-gateway / dev.kaidev.gateway
├── GatewayApplication.java
├── config/
│   └── properties/     Typed host/origin settings
└── filter/             Host/origin/CORS enforcement

api-common / dev.kaidev.common
├── api/
│   ├── code/           Shared status/message catalog
│   └── response/       Response envelope and field errors
├── exception/          Reusable business exception
├── logging/            Structured application log helpers
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
