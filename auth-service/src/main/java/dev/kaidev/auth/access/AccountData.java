package dev.kaidev.auth.access;

import dev.kaidev.auth.hardening.*;
import dev.kaidev.auth.identity.*;
import dev.kaidev.auth.repository.*;
import dev.kaidev.auth.service.SessionService;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.SecurityAudit;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AccountData {
    public record IdentityView(UUID id,String email,boolean emailVerified,boolean active,boolean locked,Set<String> roles){
        @Override public String toString(){return "ExportIdentity[REDACTED]";}
    }
    public record PersonalData(Instant exportedAt,IdentityView identity,com.fasterxml.jackson.databind.JsonNode profile,
            List<SessionView> sessions,List<DeviceRegistry.DeviceView> devices,List<ServiceCredentials.KeyView> apiKeys,
            List<Map<String,Object>> tenants,List<LoginHistory.Entry> authenticationHistory){
        @Override public String toString(){return "PersonalDataExport[REDACTED]";}
    }
    private final ReauthenticationProofs reauthentication;
    private final dev.kaidev.auth.outbox.AuthOutbox outbox;
    private final ActorSecurity security;private final LastAdministratorGuard guard;private final SessionService sessions;
    private final JdbcTemplate jdbc;private final ProfileDataClient profile;
    private final DeviceRegistry devices;private final AuthAuditStore audit;private final ServiceCredentials keys;
    private final AccountActionTokenRepository proofs;
    public AccountData(ActorSecurity security,LastAdministratorGuard guard,SessionService sessions,JdbcTemplate jdbc,
            ProfileDataClient profile,DeviceRegistry devices,AuthAuditStore audit,ServiceCredentials keys,AccountActionTokenRepository proofs,dev.kaidev.auth.outbox.AuthOutbox outbox,ReauthenticationProofs reauthentication){
        this.reauthentication=reauthentication;this.security=security;this.guard=guard;this.sessions=sessions;this.jdbc=jdbc;this.profile=profile;this.outbox=outbox;this.devices=devices;this.audit=audit;this.keys=keys;this.proofs=proofs;
    }
    @Transactional public PersonalData export(UUID owner,String password){
        var user=security.lock(owner);security.require(user,"account:export");security.reauthenticate(user,password);
        return snapshot(user);
    }
    @Transactional public PersonalData exportConfirmed(UUID owner){
        var user=security.lock(owner);security.require(user,"account:export");
        if(!reauthentication.valid(user))throw new ApiException(CommonCode.UNAUTHENTICATED);
        return snapshot(user);
    }
    private PersonalData snapshot(dev.kaidev.auth.entity.AppUser user){
        UUID owner=user.id;
        var identity=new IdentityView(user.id,user.email,user.emailVerified,user.active,user.adminLocked,Set.copyOf(user.roles));
        var personalProfile=profile.export(owner);var active=sessions.list(owner,null);
        var memberships=jdbc.queryForList("select t.id,t.name from identity_tenants t join identity_tenant_members m on m.tenant_id=t.id where m.user_id=?",owner);
        var attempts=jdbc.query("select * from authentication_history where user_id=? order by occurred_at desc,id",
                (r,n)->new LoginHistory.Entry(r.getObject("id",UUID.class),r.getTimestamp("occurred_at").toInstant(),r.getBoolean("successful"),r.getString("reason"),r.getString("ip"),r.getString("user_agent")),owner);
        return new PersonalData(Instant.now(),identity,personalProfile,active,devices.list(owner,active),keys.list(owner),memberships,attempts);
    }
    @Transactional public void requestDeletion(UUID owner,String password){
        long before=guard.acquire();var user=security.lock(owner);security.require(user,"account:delete");security.reauthenticate(user,password);
        user.active=false;user.deactivatedAt=Instant.now();user.credentialRevision++;user.deletedAt=Instant.now();guard.verify(before);
        proofs.invalidateAll(owner,Instant.now());sessions.revokeAll(owner);
        if(jdbc.queryForObject("select count(*) from identity_tenants where owner_id=?",Long.class,owner)>0)
            throw new ApiException(CommonCode.CONFLICT); // Explicitly remove owned tenants before deleting their owner.
        jdbc.update("update identity_api_keys set revoked_at=? where user_id=? and revoked_at is null",Timestamp.from(Instant.now()),owner);
        jdbc.update("insert into account_deletions(user_id,requested_at,available_at,state) values(?,?,?,'PENDING')",owner,Timestamp.from(Instant.now()),Timestamp.from(Instant.now()));
        audit.append(owner,SecurityAudit.Event.ACCOUNT_DELETION_REQUESTED,Map.of("targetUserId",owner));
    }
    @Transactional public void finishDeletion(UUID owner){
        var user=security.lock(owner);if(user.deletedAt==null)throw new IllegalStateException("Deletion was not requested");
        // Remote deletion commits a scrubbed profile tombstone before local erasure. Retrying is idempotent.
        profile.delete(owner);
        jdbc.update("delete from reauthentication_proofs where user_id=?",owner);
        jdbc.update("delete from identity_api_keys where user_id=?",owner);
        jdbc.update("delete from identity_tenant_members where user_id=?",owner);
        jdbc.update("delete from authentication_history where user_id=?",owner);
        jdbc.update("delete from identity_refresh_ledger where user_id=?",owner);
        jdbc.update("delete from identity_sessions where user_id=?",owner);
        jdbc.update("delete from identity_devices where user_id=?",owner);
        proofs.eraseFor(owner);
        outbox.cancelRecipient(user.email);
        user.roles.clear();user.email="deleted-"+owner+"@invalid.invalid";user.passwordHash="!deleted";user.emailVerified=false;
        user.emailOtpHash=null;user.emailOtpExpiresAt=null;user.emailOtpResendAt=null;user.emailOtpAttempts=0;user.passwordResetResendAt=null;user.emailChangeResendAt=null;
        jdbc.update("update account_deletions set state='COMPLETED',completed_at=? where user_id=?",Timestamp.from(Instant.now()),owner);
        audit.append(owner,SecurityAudit.Event.ACCOUNT_DELETED,Map.of("targetUserId",owner));
    }
}
