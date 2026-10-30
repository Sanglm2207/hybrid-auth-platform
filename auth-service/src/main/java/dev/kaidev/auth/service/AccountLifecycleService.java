package dev.kaidev.auth.service;

import dev.kaidev.auth.client.MailServiceClient;
import dev.kaidev.auth.config.AccountActionLinks;
import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.entity.*;
import dev.kaidev.auth.entity.AccountActionToken.Purpose;
import dev.kaidev.auth.repository.*;
import dev.kaidev.auth.security.*;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.*;
import dev.kaidev.common.util.EmailAddress;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import org.slf4j.MDC;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AccountLifecycleService {
    private static final long TOKEN_TTL_SECONDS = 900;
    private final UserRepository users;
    private final AccountActionTokenRepository tokens;
    private final PasswordEncoder passwords;
    private final MailServiceClient mail;
    private final SessionService sessions;
    private final AbuseProtection protection;
    private final ApplicationEventPublisher events;
    private final AccountActionLinks links;
    private final SecureRandom random = new SecureRandom();

    public AccountLifecycleService(UserRepository users, AccountActionTokenRepository tokens, PasswordEncoder passwords,
            MailServiceClient mail, SessionService sessions, AbuseProtection protection, ApplicationEventPublisher events, AccountActionLinks links) {
        this.users = users; this.tokens = tokens; this.passwords = passwords; this.mail = mail;
        this.sessions = sessions; this.protection = protection; this.events = events; this.links = links;
    }

    @Transactional
    public void forgotPassword(String email) {
        AppUser user = users.findByEmailForUpdate(EmailAddress.normalize(email)).orElse(null);
        if (user == null || (!user.active || user.adminLocked || user.deletedAt!=null)) return;
        Instant now = Instant.now();
        if (user.passwordResetResendAt != null && now.isBefore(user.passwordResetResendAt)) return;
        String token = issue(user, Purpose.RESET_PASSWORD, null, now);
        user.passwordResetResendAt = now.plusSeconds(60);
        proofMail(user, user.email, "password-reset", Map.of("resetUrl", links.reset(token), "expiresInMinutes", "15"));
        auditAfterCommit(user, SecurityAudit.Event.PASSWORD_RESET_REQUESTED);
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        Resolved resolved = resolve(token, Purpose.RESET_PASSWORD);
        AppUser user = resolved.user();
        updatePassword(user, newPassword);
        protection.reset(user.email); // A valid recovery proof lets the owner recover from temporary login lockout.
        finishCredentialChange(user);
        notice(user, user.email, "password-changed", Map.of());
        auditAfterCommit(user, SecurityAudit.Event.PASSWORD_RESET);
    }

    @Transactional
    public void changePassword(UUID userId, String currentPassword, String newPassword) {
        AppUser user = lockUser(userId);
        authenticate(user, currentPassword);
        updatePassword(user, newPassword);
        finishCredentialChange(user);
        notice(user, user.email, "password-changed", Map.of());
        auditAfterCommit(user, SecurityAudit.Event.PASSWORD_CHANGED);
    }

    @Transactional
    public void changeEmail(UUID userId, String currentPassword, String newEmail) {
        AppUser user = lockUser(userId);
        authenticate(user, currentPassword);
        newEmail = EmailAddress.normalize(newEmail);
        if (user.email.equals(newEmail)) throw new ApiException(AuthCode.EMAIL_UNCHANGED);
        if (users.findByEmail(newEmail).isPresent()) throw new ApiException(AuthCode.EMAIL_EXISTS);
        Instant now = Instant.now();
        if (user.emailChangeResendAt != null && now.isBefore(user.emailChangeResendAt))
            throw new ApiException(AuthCode.ACCOUNT_ACTION_COOLDOWN);
        String token = issue(user, Purpose.CHANGE_EMAIL, newEmail, now);
        user.emailChangeResendAt = now.plusSeconds(60);
        proofMail(user, newEmail, "email-change-verification", Map.of("verificationUrl", links.confirmEmail(token), "expiresInMinutes", "15"));
        notice(user, user.email, "email-change-requested", Map.of("newEmail", newEmail));
        auditAfterCommit(user, SecurityAudit.Event.EMAIL_CHANGE_REQUESTED);
    }

    @Transactional
    public void confirmEmailChange(String token) {
        Resolved resolved = resolve(token, Purpose.CHANGE_EMAIL);
        AppUser user = resolved.user();
        String oldEmail = user.email, newEmail = resolved.token().targetEmail;
        if (newEmail == null || users.findByEmail(newEmail).isPresent()) throw new ApiException(AuthCode.EMAIL_EXISTS);
        user.email = newEmail;
        user.emailVerified = true;
        user.emailOtpHash = null; user.emailOtpExpiresAt = null; user.emailOtpResendAt = null; user.emailOtpAttempts = 0;
        // Flush the unique-email constraint before touching external session state or scheduling notices.
        users.flush();
        protection.reset(oldEmail); protection.reset(newEmail);
        finishCredentialChange(user);
        notice(user, oldEmail, "email-changed", Map.of("newEmail", newEmail));
        notice(user, newEmail, "email-change-confirmed", Map.of());
        auditAfterCommit(user, SecurityAudit.Event.EMAIL_CHANGED);
    }

    private void updatePassword(AppUser user, String password) {
        if (passwords.matches(password, user.passwordHash)) throw new ApiException(AuthCode.PASSWORD_UNCHANGED);
        user.passwordHash = passwords.encode(password);
    }

    private void finishCredentialChange(AppUser user) {
        user.credentialRevision++;
        user.passwordResetResendAt = null; user.emailChangeResendAt = null;
        tokens.invalidateAll(user.id, Instant.now());
        // User row lock also serializes login/refresh, preventing old-credential issuance after this invalidation.
        // Failure rolls the SQL mutation back. Revocation and the credential mutation share the SQL transaction.
        sessions.revokeAll(user.id);
    }

    private void authenticate(AppUser user, String password) {
        if ((!user.active || user.adminLocked || user.deletedAt!=null)) throw new ApiException(AuthCode.ACCOUNT_DISABLED);
        long locked = protection.lockedFor(user.email);
        if (locked > 0) throw new TemporaryLockException(locked);
        if (!passwords.matches(password, user.passwordHash)) {
            long retry = protection.failed(user.email);
            SecurityAudit.record(SecurityAudit.Event.AUTHENTICATION_FAILURE, SecurityAudit.Outcome.DENIED,
                    user.id.toString(), MDC.get("traceId"));
            if (retry > 0) throw new TemporaryLockException(retry);
            throw new ApiException(AuthCode.INVALID_CREDENTIALS);
        }
        long retry = protection.succeeded(user.email);
        if (retry > 0) throw new TemporaryLockException(retry);
    }

    private AppUser lockUser(UUID id) {
        return users.findByIdForUpdate(id).orElseThrow(() -> new ApiException(AuthCode.INVALID_CREDENTIALS));
    }
    private record Resolved(AppUser user, AccountActionToken token) {}
    private Resolved resolve(String raw, Purpose purpose) {
        if (raw == null || !raw.matches("[A-Za-z0-9_-]{43}")) throw invalidToken();
        String hash = ClientIdentity.hash(raw);
        UUID userId = tokens.findUserIdByTokenHash(hash).orElseThrow(AccountLifecycleService::invalidToken);
        AppUser user = users.findByIdForUpdate(userId).orElseThrow(AccountLifecycleService::invalidToken);
        // Load the entity only AFTER acquiring the user lock: don't reuse a pre-lock cached token snapshot.
        AccountActionToken token = tokens.findByTokenHash(hash).orElseThrow(AccountLifecycleService::invalidToken);
        if ((!user.active || user.adminLocked || user.deletedAt!=null) || token.purpose != purpose || token.consumedAt != null || !Instant.now().isBefore(token.expiresAt)
                || token.credentialRevision != user.credentialRevision) throw invalidToken();
        return new Resolved(user, token);
    }
    private String issue(AppUser user, Purpose purpose, String targetEmail, Instant now) {
        tokens.invalidate(user.id, purpose, now);
        byte[] bytes = new byte[32]; random.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        var token = new AccountActionToken();
        token.userId = user.id; token.tokenHash = ClientIdentity.hash(raw); token.purpose = purpose;
        token.credentialRevision = user.credentialRevision; token.targetEmail = targetEmail;
        token.createdAt = now; token.expiresAt = now.plusSeconds(TOKEN_TTL_SECONDS);
        tokens.saveAndFlush(token);
        return raw;
    }
    private void proofMail(AppUser user, String to, String template, Map<String, String> variables) {
        try { mail.send(to, template, variables); }
        catch (ApiException e) {
            SecurityAudit.record(SecurityAudit.Event.ACCOUNT_MAIL_FAILURE, SecurityAudit.Outcome.FAILURE,
                    user.id.toString(), MDC.get("traceId"));
            throw e;
        }
    }
    private void notice(AppUser user, String to, String template, Map<String, String> variables) {
        events.publishEvent(new AccountMailNotifications.Notice(user.id, to, template, Map.copyOf(variables)));
    }
    private void auditAfterCommit(AppUser user, SecurityAudit.Event event) {
        events.publishEvent(new AccountMailNotifications.CommittedAudit(user.id, event));
    }
    private static ApiException invalidToken() { return new ApiException(AuthCode.INVALID_ACCOUNT_TOKEN); }

    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void cleanupExpiredTokens() { tokens.deleteExpired(Instant.now()); }
}
