package dev.kaidev.auth.identity;

import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.service.SessionService;
import dev.kaidev.common.security.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IdentityValidationService {
    private final dev.kaidev.auth.access.ServiceCredentials machineKeys;
    private final UserRepository users;
    private final SessionService sessions;
    private final RolePolicyService roles;
    public IdentityValidationService(UserRepository users, SessionService sessions, RolePolicyService roles, dev.kaidev.auth.access.ServiceCredentials machineKeys) {
        this.users = users; this.sessions = sessions; this.roles = roles; this.machineKeys=machineKeys;
    }
    // The SQL ledger may update last activity after its 30-second interval.
    @Transactional
    public IdentityAccess check(IdentityCheck request) {
        var user = users.findById(request.subject()).orElse(null);
        if (user == null || !user.active || user.adminLocked || user.deletedAt!=null || !user.emailVerified || request.credentialRevision() == null
                || user.credentialRevision != request.credentialRevision() || request.sessionVersion() == null) return IdentityAccess.denied();
        var machine=machineKeys.check(user,request);if(machine.isPresent())return machine.get();
        if(!sessions.active(user.id,request.sessionId(),request.sessionVersion(),request.credentialRevision()))return IdentityAccess.denied();
        return new IdentityAccess(true, java.util.Set.copyOf(user.roles), roles.permissions(user.roles));
    }
}
