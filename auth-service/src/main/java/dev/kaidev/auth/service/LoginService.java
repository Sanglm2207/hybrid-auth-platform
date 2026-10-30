package dev.kaidev.auth.service;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.dto.response.TokenResponse;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.security.AbuseProtection;
import dev.kaidev.auth.security.TemporaryLockException;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.SecurityAudit;
import dev.kaidev.common.util.EmailAddress;
import org.slf4j.MDC;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class LoginService {
    private final UserRepository users;
    private final PasswordEncoder passwords;
    private final SessionService sessions;
    private final AbuseProtection protection;
    private final String dummyHash;
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private dev.kaidev.auth.access.LoginHistory history;

    public LoginService(UserRepository users, PasswordEncoder passwords, SessionService sessions, AbuseProtection protection) {
        this.users = users; this.passwords = passwords; this.sessions = sessions; this.protection = protection;
        this.dummyHash = passwords.encode(java.util.UUID.randomUUID().toString());
    }

    @org.springframework.transaction.annotation.Transactional
    public TokenResponse login(String email, String password) {
        email = EmailAddress.normalize(email);
        long remaining = protection.lockedFor(email);
        if (remaining > 0) {
            if(history!=null)history.record(users.findByEmail(email).map(u->u.id).orElse(null),false,"LOCKED");
            throw locked(null, remaining);
        }
        var user = users.findByEmailForUpdate(email).orElse(null);
        String actor = user == null ? null : user.id.toString();
        // Unknown users still pay the BCrypt cost and use exactly the same lockout state machine.
        boolean matches = passwords.matches(password, user == null ? dummyHash : user.passwordHash);
        if (user == null || !matches) {
            if(history!=null)history.record(user==null?null:user.id,false,"INVALID_CREDENTIALS");
            long lock = protection.failed(email);
            audit(SecurityAudit.Event.LOGIN, SecurityAudit.Outcome.DENIED, actor);
            if (lock > 0) throw locked(actor, lock);
            throw new ApiException(AuthCode.INVALID_CREDENTIALS);
        }
        // Recheck atomically after BCrypt so a concurrent lock cannot be bypassed by an in-flight success.
        long concurrentLock = protection.succeeded(email);
        if (concurrentLock > 0) {
            if(history!=null)history.record(user.id,false,"LOCKED");throw locked(actor,concurrentLock);
        }
        if (!user.active || user.adminLocked || user.deletedAt!=null) {
            if(history!=null)history.record(user.id,false,"ACCOUNT_DISABLED");
            throw new ApiException(AuthCode.ACCOUNT_DISABLED);
        }
        if (!user.emailVerified) {
            if(history!=null)history.record(user.id,false,"EMAIL_NOT_VERIFIED");
            audit(SecurityAudit.Event.LOGIN, SecurityAudit.Outcome.DENIED, actor);
            throw new ApiException(AuthCode.EMAIL_NOT_VERIFIED);
        }
        TokenResponse response = sessions.issue(user);
        if(history!=null)history.successful(user.id);
        audit(SecurityAudit.Event.LOGIN, SecurityAudit.Outcome.SUCCESS, actor);
        return response;
    }

    private static ApiException locked(String actor, long retryMs) {
        audit(SecurityAudit.Event.ACCOUNT_LOCKED, SecurityAudit.Outcome.DENIED, actor);
        return new TemporaryLockException(retryMs);
    }
    private static void audit(SecurityAudit.Event event, SecurityAudit.Outcome outcome, String actor) {
        SecurityAudit.record(event, outcome, actor, MDC.get("correlationId"));
    }
}
