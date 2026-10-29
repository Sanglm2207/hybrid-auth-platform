package dev.kaidev.auth.identity;

import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.service.SessionService;
import dev.kaidev.common.security.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IdentityValidationService {
    private final UserRepository users;
    private final SessionService sessions;
    private final RolePolicyService roles;
    public IdentityValidationService(UserRepository users, SessionService sessions, RolePolicyService roles) {
        this.users = users; this.sessions = sessions; this.roles = roles;
    }
    // The SQL ledger may update last activity after its 30-second interval.
    @Transactional
    public IdentityAccess check(IdentityCheck request) {
        var user = users.findById(request.subject()).orElse(null);
        if (user == null || !user.active || !user.emailVerified || request.credentialRevision() == null
                || user.credentialRevision != request.credentialRevision() || request.sessionVersion() == null
                || !sessions.active(user.id, request.sessionId(), request.sessionVersion(), request.credentialRevision())) return IdentityAccess.denied();
        return new IdentityAccess(true, java.util.Set.copyOf(user.roles), roles.permissions(user.roles));
    }
}
