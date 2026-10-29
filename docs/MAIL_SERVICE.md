# Mail service

`mail-service` is a standalone Spring MVC application, running on `127.0.0.1:8703` by default. It centralizes the SMTP connection, sender address, and HTML/text email templates. Other services call its HTTP API with a template ID and plain text variables. Auth owns OTP generation, expiry, verification, and persistence; Mail only renders and sends the supplied content.

## Local configuration

Run `bash ./prepare-env.sh` before a manual launch, or use `./run-services.sh` / VS Code **All Services (Local)**. Preparation creates `.env` when missing and generates `MAIL_SERVICE_API_KEY` when empty, preserving any configured key. Auth and Mail must use the same key. The terminal runner starts Mail before Auth; the VS Code compound launches all services, so wait for them to finish startup before sending requests.

| Variable | Default / use |
| --- | --- |
| `MAIL_SERVICE_URL` | Auth's Mail base URL; `http://127.0.0.1:8703` |
| `MAIL_SERVICE_PORT` | Mail listen port; `8703`. Update `MAIL_SERVICE_URL` too when changing it. |
| `MAIL_BIND_ADDRESS` | Mail bind address; `127.0.0.1` |
| `MAIL_SERVICE_API_KEY` | Shared internal credential; generated locally, no application default |
| `SMTP_HOST`, `SMTP_PORT` | SMTP host and port; port defaults to `587` |
| `SMTP_USER`, `SMTP_PASS` | SMTP login credentials, used only by Mail |
| `SMTP_SECURE` | `false` for STARTTLS; `true` for implicit TLS |
| `MAIL_SIGNATURE` | Managed footer, default `Hybrid Auth Security Team`; nonblank single line, max 160 characters |
| `EMAIL_FROM` | Sender address, optionally `Team Name <sender@example.com>` |

All ten bundled templates include the shared sender signature. It is a visible footer, not a DKIM/cryptographic signature; configure domain signing at the SMTP provider.

Mail uses its own PostgreSQL `maildb` for idempotency receipts and has no Redis dependency. `/actuator/health` is available without a service key and reports application liveness; the SMTP health check is disabled, so it does not confirm SMTP credentials or provider availability. If the key is empty, internal API requests fail with HTTP 503. Missing or incorrect keys return HTTP 401 when a key is configured. Keep the service private; remote service-to-service deployment also needs a trusted network and TLS.

## Internal HTTP API

All endpoints use the shared JSON response envelope and `X-Request-Id` correlation header. Every endpoint below requires `X-Mail-Service-Key`. There is deliberately no Gateway route for this API.

| Method and path | Purpose | Response data |
| --- | --- | --- |
| `GET /api/v1/mail/templates` | List configured templates | Array of `{id, subject, variables}` |
| `POST /api/v1/mail/templates/{id}/preview` | Render without sending | `{subject, html, text}` |
| `POST /api/v1/mail/send` | Render and submit one email to SMTP | `null`; HTTP 200 with `MAIL_SENT` |

Template catalog:

| ID | Variables | Automatic caller |
| --- | --- | --- |
| `email-verification` | `otp`, `expiresInMinutes` | Auth registration and resend OTP |
| `welcome` | `displayName`, `appName` | None; available for future callers |
| `password-reset` | `resetToken`, `expiresInMinutes` | Forgot-password worker |
| `password-changed` | None | After committed password reset/change |
| `email-change-verification` | `verificationToken`, `expiresInMinutes` | Pending email change, new inbox |
| `email-change-requested` | `newEmail` | Pending email change, current inbox |
| `email-changed` | `newEmail` | Confirmed email change, old inbox |
| `email-change-confirmed` | None | Confirmed email change, new inbox |
| `account-deactivated` | None | Committed account deactivation |
| `roles-changed` | None | Committed role assignment change |

Export local settings into the current shell before using these examples:

```bash
set -a
source .env
set +a

curl http://127.0.0.1:8703/api/v1/mail/templates \
  -H "X-Mail-Service-Key: $MAIL_SERVICE_API_KEY"

curl -X POST http://127.0.0.1:8703/api/v1/mail/templates/welcome/preview \
  -H "X-Mail-Service-Key: $MAIL_SERVICE_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"variables":{"displayName":"Kai","appName":"Hybrid Auth"}}'
```

Send a templated email from any internal service using this request shape:

```http
POST /api/v1/mail/send
Content-Type: application/json
X-Mail-Service-Key: <shared-internal-key>
X-Request-Id: 12345678-1234-1234-1234-123456789abc

{
  "to": "recipient@example.com",
  "templateId": "welcome",
  "variables": {
    "displayName": "Kai",
    "appName": "Hybrid Auth"
  }
}
```

The sender, subject pattern, and template resource paths belong to Mail configuration. Callers cannot override them or submit arbitrary HTML. Only a single validated recipient is accepted per request. Variables must contain exactly the keys required by the selected template; values must be nonblank strings, up to 4096 characters each, with at most 32 entries per request. Unknown JSON fields and scalar coercion are rejected.

## Configure a new template

Templates are version-controlled resources and configuration, loaded at Mail startup. Templates have no database or runtime CRUD endpoint for editing; the database stores delivery receipts only.

1. Add HTML and UTF-8 plain text files under `mail-service/src/main/resources/templates/email/`, for example `password-reset.html` and `password-reset.txt`.
2. Include a `{{signature}}` footer in both HTML and text. Mail injects this reserved variable from `MAIL_SIGNATURE`; callers cannot override it. It is excluded from required caller variables. Use `{{variableName}}` placeholders for other content. Names start with a letter and contain letters, digits, or underscores, up to 64 characters. Variables are inferred from the subject, HTML, and text together. The renderer supports substitution only: no expressions, loops, includes, or executable code.
3. Register a template ID in Mail's `application.yml`:

   ```yaml
   app:
     mail:
       templates:
         password-reset:
           subject: "Your password reset code"
           html: classpath:templates/email/password-reset.html
           text: classpath:templates/email/password-reset.txt
   ```

4. Rebuild and restart Mail, check `GET /templates`, then preview the template with all required variables before calling `/send`. Other services only need the template ID and variables; Auth needs no code change for templates it does not use.

Resource locations also support `file:/absolute/path/template.html` and a matching text file for deployment-managed templates. Paths come from trusted service configuration, never from request input. Missing resources and malformed placeholders fail startup. Template IDs use lowercase letters, digits, and hyphens, starting with a letter, up to 64 characters.

HTML variable values are escaped and inserted once, so caller-supplied tags and placeholder-like text are not executed or expanded. Put placeholders in text nodes or ordinary quoted text attributes; URL/CSS/JavaScript contexts are not supported. Templates themselves are trusted HTML. Text alternatives preserve plain text values. Rendered subjects reject line breaks to prevent mail-header injection. Preview responses may contain sensitive data, so treat them like email content.

## Delivery and failure behavior

Mail builds a UTF-8 multipart message with both HTML and text alternatives. `MAIL_SENT` means the SMTP server accepted the message; it does not confirm arrival in the recipient's inbox.

| Code | HTTP status | Meaning |
| --- | --- | --- |
| `MAIL_SENT` | 200 | Submitted successfully |
| `MAIL_NOT_CONFIGURED` | 503 | Missing service key, SMTP host, or sender configuration |
| `MAIL_DELIVERY_FAILED` | 503 | SMTP authentication, connection, or send failure |
| `TEMPLATE_NOT_FOUND` | 404 | Template ID is not registered |
| `TEMPLATE_VARIABLES_INVALID` | 400 | Missing/extra variables or invalid rendered subject |
| `VALIDATION_FAILED` / `INVALID_REQUEST` | 400 | Request validation or JSON parsing failure |
| `UNAUTHENTICATED` | 401 | Missing, incorrect, or duplicate service-key header |

Auth's `MailServiceClient` propagates the request ID, uses a two-second connection timeout and a 20-second read timeout, and requires a successful `MAIL_SENT` acknowledgement. It does not retry automatically. A missing Auth-side service key returns `EMAIL_NOT_CONFIGURED`; remote errors, timeouts, or invalid acknowledgements become `EMAIL_DELIVERY_FAILED` (HTTP 503), without exposing Mail's response body. Registration rolls back; failed resend preserves the previous OTP and cooldown state.

Mail accepts synchronous internal submissions with an optional UUID `Idempotency-Key`. Auth supplies a stable ID from its durable encrypted outbox and retries failures. Successful matching submissions are skipped using SQL receipts; different content with the same ID returns 409. A provider acceptance/receipt-commit crash can still cause duplicates. SMTP acceptance does not prove inbox delivery. See [durable mail, database roles, failure drills and operations](HARDENING_RELIABILITY.md).
