package dev.kaidev.auth.identity;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.*;
import dev.kaidev.auth.security.*;
import dev.kaidev.auth.service.*;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.SecurityAudit;
import java.time.Instant;
import java.util.*;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IdentityManagementService {
    private final dev.kaidev.auth.hardening.LastAdministratorGuard adminGuard;
    private final UserRepository users;
    private final RoleRepository roles;
    private final RolePolicyService policies;
    private final DeviceRepository devices;
    private final SessionService sessions;
    private final AccountActionTokenRepository tokens;
    private final PasswordEncoder passwords;
    private final AbuseProtection protection;
    private final ApplicationEventPublisher events;
    public IdentityManagementService(UserRepository users, RoleRepository roles, RolePolicyService policies, DeviceRepository devices,
            SessionService sessions, AccountActionTokenRepository tokens, PasswordEncoder passwords, AbuseProtection protection,
            ApplicationEventPublisher events, dev.kaidev.auth.hardening.LastAdministratorGuard adminGuard) {
        this.adminGuard = adminGuard;
        this.users = users; this.roles = roles; this.policies = policies; this.devices = devices; this.sessions = sessions;
        this.tokens = tokens; this.passwords = passwords; this.protection = protection; this.events = events;
    }
    @Transactional
    public void deactivate(UUID actor, String password) {
        long managers = adminGuard.acquire();
        var user = lock(actor); authenticate(user, password);
        user.active = false; user.deactivatedAt = Instant.now(); user.credentialRevision++;
        adminGuard.verify(managers);
        tokens.invalidateAll(user.id, Instant.now()); sessions.revokeAll(user.id);
        events.publishEvent(new AccountMailNotifications.Notice(user.id, user.email, "account-deactivated", Map.of()));
        audit(user.id, SecurityAudit.Event.ACCOUNT_DEACTIVATED);
    }
    @Transactional
    public void revokeDevice(UUID owner, UUID device) {
        lock(owner);
        var record = devices.findByUserIdAndDeviceId(owner, device).orElseThrow(() -> new ApiException(AuthCode.DEVICE_NOT_FOUND));
        for (var session : sessions.list(owner, null)) if (session.deviceId().equals(device)) sessions.revokeSession(owner, session.id());
        devices.delete(record); audit(owner, SecurityAudit.Event.DEVICE_REVOKED,Map.of("targetUserId",owner,"deviceId",device));
    }
    @Transactional
    public Set<String> assignRoles(UUID actorId, UUID targetId, Set<String> assigned, String password) {
        long managers = adminGuard.acquire();
        // Stable lock order avoids deadlocks when two administrators modify each other.
        Map<UUID, AppUser> locked = new HashMap<>();
        java.util.stream.Stream.of(actorId, targetId).distinct().sorted().forEach(id -> locked.put(id, lock(id)));
        var actor = locked.get(actorId); authenticate(actor, password); requireManager(actor);
        if (assigned == null || assigned.isEmpty() || assigned.size() > 16 || assigned.stream().anyMatch(Objects::isNull) || roles.findAllById(assigned).size() != assigned.size())
            throw new ApiException(AuthCode.INVALID_ROLE_POLICY);
        var target = locked.get(targetId);
        Set<String> before=Set.copyOf(target.roles);
        target.roles = new HashSet<>(assigned); target.credentialRevision++;
        adminGuard.verify(managers);
        tokens.invalidateAll(target.id, Instant.now()); sessions.revokeAll(target.id);
        events.publishEvent(new AccountMailNotifications.Notice(target.id, target.email, "roles-changed", Map.of()));
        audit(actorId, SecurityAudit.Event.ROLES_CHANGED,Map.of("targetUserId",targetId,"rolesBefore",before,"rolesAfter",assigned));
        return Set.copyOf(target.roles);
    }
    @Transactional
    public RolePolicyService.RoleView saveRole(UUID actorId, String name, Set<String> permissions, String password, boolean create) {
        long managers = adminGuard.acquire();
        var actor = lock(actorId); authenticate(actor, password); requireManager(actor);
        if (name == null || !name.matches("[A-Z][A-Z0-9_]{0,31}") || permissions == null || !Permissions.ALL.containsAll(permissions)
                || (name.equals("ADMIN") && !permissions.contains("roles:manage"))) throw new ApiException(AuthCode.INVALID_ROLE_POLICY);
        var existing = roles.findById(name);
        if (create && existing.isPresent()) throw new ApiException(CommonCode.CONFLICT);
        if (!create && existing.isEmpty()) throw new ApiException(CommonCode.NOT_FOUND);
        var role = existing.orElseGet(() -> new RoleDefinition(name, permissions));
        Set<String> before=existing.map(r->Set.copyOf(r.permissions)).orElse(Set.of());
        role.permissions = new HashSet<>(permissions); roles.saveAndFlush(role);
        adminGuard.verify(managers);
        audit(actorId, SecurityAudit.Event.ROLE_POLICY_CHANGED,Map.of("role",name,"permissionsBefore",before,"permissionsAfter",permissions));
        return new RolePolicyService.RoleView(role.name, Set.copyOf(role.permissions));
    }
    private void requireManager(AppUser actor) {
        if (!policies.permissions(actor.roles).contains("roles:manage")) throw new ApiException(CommonCode.ACCESS_DENIED);
    }
    private AppUser lock(UUID id) { return users.findByIdForUpdate(id).orElseThrow(() -> new ApiException(CommonCode.NOT_FOUND)); }
    private void authenticate(AppUser user, String password) {
        if (!user.active || user.adminLocked || user.deletedAt!=null) throw new ApiException(AuthCode.ACCOUNT_DISABLED);
        long retry = protection.lockedFor(user.email); if (retry > 0) throw new TemporaryLockException(retry);
        if (!passwords.matches(password, user.passwordHash)) {
            retry = protection.failed(user.email); if (retry > 0) throw new TemporaryLockException(retry);
            throw new ApiException(AuthCode.INVALID_CREDENTIALS);
        }
        retry = protection.succeeded(user.email); if (retry > 0) throw new TemporaryLockException(retry);
    }
    private void audit(UUID actor,SecurityAudit.Event event,Map<String,?> details) { events.publishEvent(new AccountMailNotifications.CommittedAudit(actor,event,details)); }
    private void audit(UUID actor, SecurityAudit.Event event) { events.publishEvent(new AccountMailNotifications.CommittedAudit(actor, event)); }
}
