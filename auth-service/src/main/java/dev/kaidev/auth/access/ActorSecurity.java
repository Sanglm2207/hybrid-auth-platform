package dev.kaidev.auth.access;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.identity.RolePolicyService;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.security.*;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/** Must run inside the mutation's transaction; never grants permissions from JWT role claims. */
@Service
public class ActorSecurity {
    private final UserRepository users;
    private final RolePolicyService policies;
    private final PasswordEncoder passwords;
    private final AbuseProtection abuse;
    public ActorSecurity(UserRepository users, RolePolicyService policies, PasswordEncoder passwords, AbuseProtection abuse) {
        this.users=users; this.policies=policies; this.passwords=passwords; this.abuse=abuse;
    }
    public AppUser lock(UUID id) { return users.findByIdForUpdate(id).orElseThrow(()->new ApiException(CommonCode.NOT_FOUND)); }
    public void require(AppUser actor,String permission) {
        if(!actor.active || actor.adminLocked || actor.deletedAt!=null || !actor.emailVerified)
            throw new ApiException(CommonCode.UNAUTHENTICATED);
        if(!policies.permissions(actor.roles).contains(permission)) throw new ApiException(CommonCode.ACCESS_DENIED);
    }
    public void reauthenticate(AppUser actor,String password) {
        if(!actor.active || actor.adminLocked || actor.deletedAt!=null) throw new ApiException(CommonCode.UNAUTHENTICATED);
        long remaining=abuse.lockedFor(actor.email); if(remaining>0) throw new TemporaryLockException(remaining);
        if(password==null || !passwords.matches(password,actor.passwordHash)) {
            remaining=abuse.failed(actor.email); if(remaining>0) throw new TemporaryLockException(remaining);
            throw new ApiException(AuthCode.INVALID_CREDENTIALS);
        }
        remaining=abuse.succeeded(actor.email); if(remaining>0) throw new TemporaryLockException(remaining);
    }
}
