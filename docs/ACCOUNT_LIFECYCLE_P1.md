# P1 account lifecycle

**P2 update:** the current system additionally checks live account/session state on JWT-bearing requests. Session revocation, credential changes and deactivation now reject old JWTs on subsequent checks; User stores profiles in its own database. Historical stateless-access limitations below are superseded by [P2 session and identity management](SESSION_IDENTITY_P2.md).

Email verification and resend were already implemented and are retained. Registration still uses a random six-digit, single-use OTP stored as a BCrypt hash, with a five-minute TTL, five attempts, and a 60-second resend cooldown. `/resend-verification` is an alias for the existing `/resend-otp`; both use the same service and state.

P1 adds forgot/reset password, authenticated password changes, and email changes confirmed through the new inbox. All URLs below start with `/api/v1/auth`.

| Endpoint | Authentication and JSON fields | Success code |
| --- | --- | --- |
| `POST /verify-email` | Public: `email`, `otp` | `EMAIL_VERIFIED` |
| `POST /resend-verification` or `/resend-otp` | Public: `email` | `OTP_REQUESTED` |
| `POST /forgot-password` | Public: `email` | `PASSWORD_RESET_REQUESTED` |
| `POST /reset-password` | Public: `token`, `newPassword` | `PASSWORD_RESET` |
| `POST /change-password` | Bearer JWT: `currentPassword`, `newPassword` | `PASSWORD_CHANGED` |
| `POST /change-email` | Bearer JWT: `currentPassword`, `newEmail` | `EMAIL_CHANGE_REQUESTED` |
| `POST /confirm-email-change` | Public: `token` submitted automatically by the confirmation page | `EMAIL_CHANGED` |

All success responses are HTTP 200 with the shared envelope and `data: null`. No endpoint returns a reset/verification secret or signs the user in automatically. New passwords use the existing policy: at least 12 Unicode code points, at most 72 UTF-8 bytes. Current-password fields accept existing passwords up to the same byte limit. Unknown request fields, including a caller-supplied `userId`, are rejected. Protected changes derive the account from the verified JWT subject.

## Forgot and reset password

1. Submit `{ "email": "owner@example.com" }` to `/forgot-password`.
2. The HTTP request places work in a durable encrypted PostgreSQL outbox **before any account lookup or SMTP call** and returns the same generic response for known and unknown emails. Workers propagate the request trace ID. Storage failure returns a generic HTTP 503, independently of account existence.
3. For an existing account outside its 60-second cooldown, a worker generates a 32-byte random opaque token, stores only its SHA-256 hash in PostgreSQL, and sends the `password-reset` template to the account email. Another accepted request after the cooldown replaces the old reset token. Unknown accounts and requests within cooldown send nothing. Delivery failures roll the token/cooldown transaction back and are recorded without changing the already returned public response.
4. The email contains a **Reset password** button. Open it within 15 minutes, enter and confirm a new password, and submit. The hosted page automatically sends `{ "token": "<proof from link>", "newPassword": "<new password>" }` to `POST /reset-password`; the user never copies a token or calls an API. A public `GET /forgot-password` page also accepts recovery requests.
5. Auth changes the BCrypt password hash, increments the credential revision, invalidates every pending reset/email-change token, clears temporary login lockout, and revokes all refresh sessions. The user must log in with the new password. Reset does not implicitly verify an unverified account email.
6. After commit, the account receives the `password-changed` security notification. Passwords themselves are never included in email.

The reset token is not a JWT. An access JWT cannot be used as a reset proof. Invalid, expired, already used, superseded, wrong-purpose, or old-credential-revision tokens return the same HTTP 400 `INVALID_ACCOUNT_TOKEN`. New passwords equal to the current password return HTTP 400 `PASSWORD_UNCHANGED` without consuming the proof.

Recovery and mail jobs survive process restarts. Workers claim with SQL leases, retry delivery and erase expired/completed payloads. See [hardening operations](HARDENING_RELIABILITY.md).

## Change password

Send a valid access JWT and `{ "currentPassword": "...", "newPassword": "..." }` to `/change-password`. A wrong current password returns HTTP 401 `INVALID_CREDENTIALS`. Reauthentication shares P0's failed-attempt counters and temporary lockout; a locked account returns HTTP 429 with `Retry-After`.

After the password changes, all refresh sessions and pending lifecycle tokens are invalidated. A `password-changed` notification is sent after commit. A valid recovery token can reset the password even while ordinary login/current-password checks are temporarily locked, letting the inbox owner recover access.

## Change email

1. With a valid access JWT, submit `{ "currentPassword": "...", "newEmail": "new@example.com" }` to `/change-email`.
2. Auth verifies the password, normalizes the address, and rejects the current address (`EMAIL_UNCHANGED`, HTTP 400) or an already registered address (`EMAIL_EXISTS`, HTTP 409).
3. The current account email stays active. A **Confirm email address** button is sent to the **new** inbox using `email-change-verification`. Its link contains a single-use proof valid for 15 minutes. The current inbox receives `email-change-requested` after the pending-change transaction commits.
4. Open the email button, then explicitly click **Confirm email address** on the hosted page. The page automatically submits the proof to `POST /confirm-email-change`. Opening or scanning the link alone never changes the account. This endpoint is public because the one-time proof establishes new-inbox ownership; the request cannot choose an account or target address.
5. Auth rechecks address availability and the token's purpose, expiry, use state, and credential revision. Only then does it change and verify the account email, clear old OTP state, invalidate all pending lifecycle tokens, and revoke all refresh sessions.
6. The old inbox receives `email-changed`; the new inbox receives `email-change-confirmed`. Future logins use the new address and the existing password.

Repeat `/change-email` with the current password after 60 seconds to resend or choose a different target. A replacement invalidates the previous pending email-change token. Requests during cooldown return HTTP 429 `ACCOUNT_ACTION_COOLDOWN`. If the target is registered by another account before confirmation, confirmation returns HTTP 409 and leaves the current email unchanged; the database unique constraint handles concurrent claims of the same address.

A password reset/change invalidates pending email changes. A confirmed email change invalidates reset proofs sent to the old inbox. This workflow uses current-password reauthentication, new-inbox confirmation, and notifications to the old inbox; it does not require a separate approval token from the old inbox.

## Storage, concurrency, and sessions

Flyway migration `V3__account_lifecycle.sql` adds the credential revision/cooldown columns and `account_action_tokens`. Token records hold only a hash, purpose, user ID, issuing revision, optional target email, timestamps, and consumption state. Expired token records are deleted hourly. Neither token records nor request/event `toString()` methods expose raw proofs.

Each sensitive mutation locks the user row. Token lookup first reads only its user ID; after acquiring the user lock, it loads the current token record, so a pre-lock cached entity cannot bypass replacement/invalidation. Concurrent uses of one proof have only one winner.

Login password validation and refresh issuance also lock the same user row in their SQL transaction. An old-password login cannot finish minting a session after a password reset has revoked the account's sessions; in-flight login/refresh operations finish before the credential mutation, or observe its new state afterward.

Refresh revocation, credential changes, proof consumption and encrypted mail jobs commit together in SQL. SMTP runs afterward; transient failures retry. Redis loss cannot undo SQL revocation.

**P2 update:** existing JWTs are now rejected on subsequent live state checks after credential changes or deactivation. The P1 mutation and refresh-revocation rules are unchanged; see the P2 guide for availability and in-flight request limits.

## Signed email templates

Every bundled HTML and text template now contains a managed `{{signature}}` footer. Configure it once in Mail service:

```dotenv
MAIL_SIGNATURE="Hybrid Auth Security Team"
```

Signature values are escaped in HTML, must be nonblank single-line text of at most 160 characters, and are injected by Mail. Callers cannot override `signature`, and it does not appear in the template's required caller variables. A template missing the signature in either HTML or text fails Mail startup.

| Template | Caller variables | Recipient / trigger |
| --- | --- | --- |
| `email-verification` | `otp`, `expiresInMinutes` | Existing registration/resend verification |
| `welcome` | `displayName`, `appName` | Available to internal callers; not automatic |
| `password-reset` | `resetUrl`, `expiresInMinutes` | Account inbox, recovery request |
| `password-changed` | None | Account inbox, committed reset/change |
| `email-change-verification` | `verificationUrl`, `expiresInMinutes` | New inbox, pending email change |
| `email-change-requested` | `newEmail` | Current inbox, pending-change notification |
| `email-changed` | `newEmail` | Old inbox, committed change |
| `email-change-confirmed` | None | New inbox, committed change |

The signature is a configured sender footer, not a cryptographic email signature. SMTP-domain DKIM/SPF/DMARC configuration belongs to the sending provider/deployment.

Action emails contain buttons in HTML and full links in the plain-text alternative. Public pages are hosted at `GET /api/v1/auth/forgot-password`, `/reset-password`, and `/confirm-email-change`. They show success, validation, expired/used-link, and connection-error messages. Reset requires password confirmation; email change requires an explicit confirmation click. Completed changes direct users back to their app to sign in.

Configure `ACCOUNT_PUBLIC_BASE_URL` in Auth and Gateway to the exact public origin serving the gateway (default `http://localhost:8700`, e.g. `https://accounts.example.com` in production). Only HTTPS origins are accepted except HTTP loopback for local development; do not include a path, query, fragment, or credentials. Links never use incoming Host/forwarded headers. Configure the corresponding hostname in `GATEWAY_ALLOWED_HOSTS`. Gateway includes this public origin alongside `GATEWAY_ALLOWED_ORIGINS`; origin enforcement still applies to form POSTs. Public page/script GET requests allow normal email navigation without an Origin header even with `GATEWAY_REQUIRE_ORIGIN=true`.

Proofs travel in URL fragments (`#token=...`), are removed from browser history on page initialization, and remain only in page memory until submission. They are never placed in HTTP URL queries, access logs, browser storage, visible form fields, or external assets. Reloading a page requires reopening the email link. Pages use `no-store`, `no-referrer`, and a restrictive CSP. Backend proof hashing, expiry, replacement and session revocation remain unchanged; existing POST API contracts are preserved.

Deploy Auth, Gateway, and Mail together because the two mail templates now require `resetUrl` / `verificationUrl` instead of raw proof variables. Request fresh action emails after upgrading; already queued legacy template payloads use the old variables.

Proof and notice jobs must be enqueued in the account SQL transaction before commit. Enqueue failure rolls the mutation back; SMTP failure afterward retries through the outbox. Delivery IDs are stable across retries and Mail keeps successful receipts.

## Configuration and operations

| Setting | Default |
| --- | --- |
| `ACCOUNT_PUBLIC_BASE_URL` | `http://localhost:8700`; public HTTPS gateway origin in production |
| `MAIL_SIGNATURE` | `Hybrid Auth Security Team` |
| `MAIL_OUTBOX_ENCRYPTION_KEY` | Generated AES-256 key; retain across restarts |
| `app.outbox.poll-ms` | 1000 |
| Reset/email-change token TTL | 15 minutes |
| Proof-email resend cooldown | 60 seconds |

P0 IP throttling still applies to these POST endpoints. Audit events include `PASSWORD_RESET_REQUESTED`, `PASSWORD_RESET`, `PASSWORD_CHANGED`, `EMAIL_CHANGE_REQUESTED`, `EMAIL_CHANGED`, `ACCOUNT_MAIL_FAILURE`, and `ACCOUNT_RECOVERY_FAILURE`, without emails/passwords/tokens in their payloads.

Restart Auth, Gateway, and Mail to apply the new endpoints/templates; Auth runs the schema migration automatically. V5 requires a new login for SQL session ledgers; OTP verification contracts are retained. Run `mvn verify` for token lifetime/purpose/replay/concurrency, rollback, session ordering, HTTP authorization, queue dispatch, and signed HTML/text template tests. Run `node --test auth-service/src/test/js/account-actions.test.cjs` for page behavior: explicit confirmation, password confirmation/length, automatic proof submission, expired links, duplicate submission and network errors.

References: [OWASP password recovery](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) and [OWASP reauthentication for sensitive changes](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
