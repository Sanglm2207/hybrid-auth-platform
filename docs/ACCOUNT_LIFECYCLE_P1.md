# P1 account lifecycle

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
| `POST /confirm-email-change` | Public: `token` from the new email | `EMAIL_CHANGED` |

All success responses are HTTP 200 with the shared envelope and `data: null`. No endpoint returns a reset/verification secret or signs the user in automatically. New passwords use the existing policy: at least 12 Unicode code points, at most 72 UTF-8 bytes. Current-password fields accept existing passwords up to the same byte limit. Unknown request fields, including a caller-supplied `userId`, are rejected. Protected changes derive the account from the verified JWT subject.

## Forgot and reset password

1. Submit `{ "email": "owner@example.com" }` to `/forgot-password`.
2. The HTTP request places work in a bounded in-memory executor **before any account lookup or SMTP call** and returns the same generic response for known and unknown emails. Workers propagate the request trace ID. A full queue returns a generic HTTP 503, independently of account existence.
3. For an existing account outside its 60-second cooldown, a worker generates a 32-byte random opaque token, stores only its SHA-256 hash in PostgreSQL, and sends the `password-reset` template to the account email. Another accepted request after the cooldown replaces the old reset token. Unknown accounts and requests within cooldown send nothing. Delivery failures roll the token/cooldown transaction back and are recorded without changing the already returned public response.
4. Submit `{ "token": "<token from email>", "newPassword": "<new password>" }` to `/reset-password` within 15 minutes.
5. Auth changes the BCrypt password hash, increments the credential revision, invalidates every pending reset/email-change token, clears temporary login lockout, and revokes all refresh sessions. The user must log in with the new password. Reset does not implicitly verify an unverified account email.
6. After commit, the account receives the `password-changed` security notification. Passwords themselves are never included in email.

The reset token is not a JWT. An access JWT cannot be used as a reset proof. Invalid, expired, already used, superseded, wrong-purpose, or old-credential-revision tokens return the same HTTP 400 `INVALID_ACCOUNT_TOKEN`. New passwords equal to the current password return HTTP 400 `PASSWORD_UNCHANGED` without consuming the proof.

The queue is local process memory, not a durable job system. Shutdown waits up to 20 seconds for queued work; a crash or an overloaded shutdown can lose accepted recovery requests. There is no delivery-status API or automatic retry; the user can request again after the cooldown. For durable acceptance, replace dispatch with a persistent queue/outbox.

## Change password

Send a valid access JWT and `{ "currentPassword": "...", "newPassword": "..." }` to `/change-password`. A wrong current password returns HTTP 401 `INVALID_CREDENTIALS`. Reauthentication shares P0's failed-attempt counters and temporary lockout; a locked account returns HTTP 429 with `Retry-After`.

After the password changes, all refresh sessions and pending lifecycle tokens are invalidated. A `password-changed` notification is sent after commit. A valid recovery token can reset the password even while ordinary login/current-password checks are temporarily locked, letting the inbox owner recover access.

## Change email

1. With a valid access JWT, submit `{ "currentPassword": "...", "newEmail": "new@example.com" }` to `/change-email`.
2. Auth verifies the password, normalizes the address, and rejects the current address (`EMAIL_UNCHANGED`, HTTP 400) or an already registered address (`EMAIL_EXISTS`, HTTP 409).
3. The current account email stays active. A new single-use, 15-minute opaque token is sent to the **new** inbox using `email-change-verification`. The current inbox receives `email-change-requested` after the pending-change transaction commits.
4. Submit `{ "token": "<token from new inbox>" }` to `/confirm-email-change`. This endpoint is public because the one-time secret proves new-inbox ownership; the request cannot choose an account or target address.
5. Auth rechecks address availability and the token's purpose, expiry, use state, and credential revision. Only then does it change and verify the account email, clear old OTP state, invalidate all pending lifecycle tokens, and revoke all refresh sessions.
6. The old inbox receives `email-changed`; the new inbox receives `email-change-confirmed`. Future logins use the new address and the existing password.

Repeat `/change-email` with the current password after 60 seconds to resend or choose a different target. A replacement invalidates the previous pending email-change token. Requests during cooldown return HTTP 429 `ACCOUNT_ACTION_COOLDOWN`. If the target is registered by another account before confirmation, confirmation returns HTTP 409 and leaves the current email unchanged; the database unique constraint handles concurrent claims of the same address.

A password reset/change invalidates pending email changes. A confirmed email change invalidates reset proofs sent to the old inbox. This workflow uses current-password reauthentication, new-inbox confirmation, and notifications to the old inbox; it does not require a separate approval token from the old inbox.

## Storage, concurrency, and sessions

Flyway migration `V3__account_lifecycle.sql` adds the credential revision/cooldown columns and `account_action_tokens`. Token records hold only a hash, purpose, user ID, issuing revision, optional target email, timestamps, and consumption state. Expired token records are deleted hourly. Neither token records nor request/event `toString()` methods expose raw proofs.

Each sensitive mutation locks the user row. Token lookup first reads only its user ID; after acquiring the user lock, it loads the current token record, so a pre-lock cached entity cannot bypass replacement/invalidation. Concurrent uses of one proof have only one winner.

Login password validation and refresh issuance also lock the same user row in their SQL transaction. An old-password login cannot finish minting a session after a password reset has revoked the account's sessions; in-flight login/refresh operations finish before the credential mutation, or observe its new state afterward.

Refresh revocation is performed before committing the SQL credential change. Redis failure aborts the SQL mutation, preserving the previous password/email and token use state. SQL and Redis are not a distributed transaction: a later SQL failure can revoke extra sessions, which is safe but requires a new login. Proof-email submission also cannot commit atomically with SQL; an email can be accepted before a later SQL failure. No durable outbox is implemented.

**Existing access JWTs remain usable until expiry plus validator clock skew.** P1 revokes future refreshes and requires the current password for authenticated sensitive changes; it does not add per-request access-token introspection or a denylist.

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
| `password-reset` | `resetToken`, `expiresInMinutes` | Account inbox, recovery request |
| `password-changed` | None | Account inbox, committed reset/change |
| `email-change-verification` | `verificationToken`, `expiresInMinutes` | New inbox, pending email change |
| `email-change-requested` | `newEmail` | Current inbox, pending-change notification |
| `email-changed` | `newEmail` | Old inbox, committed change |
| `email-change-confirmed` | None | New inbox, committed change |

The signature is a configured sender footer, not a cryptographic email signature. SMTP-domain DKIM/SPF/DMARC configuration belongs to the sending provider/deployment.

Templates show copyable opaque tokens for these API-based flows; this repository does not add a frontend reset/confirmation page or construct links from incoming Host headers. Add a fixed, trusted frontend URL and proper URL-context encoding if introducing clickable links later.

Proof mail must be submitted successfully before its SQL transaction commits. Notifications about completed changes use after-commit listeners: a notification failure is audited and cannot undo the committed account update or make the API report that the update failed. Notifications are best-effort and synchronous after commit; delivery retries/history remain outside this implementation.

## Configuration and operations

| Setting | Default |
| --- | --- |
| `MAIL_SIGNATURE` | `Hybrid Auth Security Team` |
| `app.account.recovery-workers` | 2 |
| `app.account.recovery-queue-capacity` | 100 |
| Reset/email-change token TTL | 15 minutes |
| Proof-email resend cooldown | 60 seconds |

P0 IP throttling still applies to these POST endpoints. Audit events include `PASSWORD_RESET_REQUESTED`, `PASSWORD_RESET`, `PASSWORD_CHANGED`, `EMAIL_CHANGE_REQUESTED`, `EMAIL_CHANGED`, `ACCOUNT_MAIL_FAILURE`, and `ACCOUNT_RECOVERY_FAILURE`, without emails/passwords/tokens in their payloads.

Restart Auth, Gateway, and Mail to apply the new endpoints/templates; Auth runs the schema migration automatically. Existing P0 Redis session format and registration verification codes are retained. Run `mvn verify` for token lifetime/purpose/replay/concurrency, rollback, session ordering, HTTP authorization, queue dispatch, and signed HTML/text template tests.

References: [OWASP password recovery](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) and [OWASP reauthentication for sensitive changes](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
