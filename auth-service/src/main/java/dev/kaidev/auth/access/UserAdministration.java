package dev.kaidev.auth.access;

import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.hardening.*;
import dev.kaidev.auth.repository.*;
import dev.kaidev.auth.service.SessionService;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.SecurityAudit;
import java.time.Instant;
import java.util.*;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserAdministration {
    public record UserView(UUID id,String email,boolean emailVerified,boolean active,boolean locked,AccountStatus status,Set<String> roles) {
        @Override public String toString(){return "UserView[REDACTED]";}
    }
    private final org.springframework.jdbc.core.JdbcTemplate jdbc;
    private final UserRepository users;
    private final ActorSecurity security;
    private final LastAdministratorGuard guard;
    private final SessionService sessions;
    private final AccountActionTokenRepository proofs;
    private final AuthAuditStore audit;
    public UserAdministration(UserRepository users,ActorSecurity security,LastAdministratorGuard guard,
            SessionService sessions,AccountActionTokenRepository proofs,AuthAuditStore audit,org.springframework.jdbc.core.JdbcTemplate jdbc) {
        this.users=users;this.security=security;this.guard=guard;this.sessions=sessions;this.proofs=proofs;this.audit=audit;this.jdbc=jdbc;
    }
    @Transactional(readOnly=true)
    public List<UserView> search(String q,Boolean locked,Boolean active,AccountStatus status,String sort,int page,int size) {
        if(q==null || q.length()>100 || page<0 || page>10000 || size<1 || size>100)throw new ApiException(CommonCode.INVALID_REQUEST);
        if(status!=null){
            if((status!=AccountStatus.DISABLED&&locked!=null&&locked!=status.locked())||(active!=null&&active!=status.active()))throw new ApiException(CommonCode.INVALID_REQUEST);
            if(status!=AccountStatus.DISABLED)locked=status.locked();active=status.active();
        }
        var parts=sort==null?new String[0]:sort.split(",",-1);
        var fields=Map.of("email","email","id","id","active","active","locked","adminLocked","emailVerified","emailVerified");
        if(parts.length!=2||!fields.containsKey(parts[0])||!Set.of("asc","desc").contains(parts[1].toLowerCase(Locale.ROOT)))throw new ApiException(CommonCode.INVALID_REQUEST);
        var order=org.springframework.data.domain.Sort.by(org.springframework.data.domain.Sort.Direction.fromString(parts[1]),fields.get(parts[0]));
        if(!parts[0].equals("id"))order=order.and(org.springframework.data.domain.Sort.by("id"));
        return users.search(q.toLowerCase(Locale.ROOT),locked,active,PageRequest.of(page,size,order)).stream().map(this::view).toList();
    }
    @Transactional
    public UserView status(UUID actorId,UUID targetId,boolean locked,boolean active,String password) {
        long before=guard.acquire(); var held=new HashMap<UUID,AppUser>();
        java.util.stream.Stream.of(actorId,targetId).distinct().sorted().forEach(id->held.put(id,security.lock(id)));
        var actor=held.get(actorId);security.require(actor,"users:update");security.reauthenticate(actor,password);
        var target=held.get(targetId);if(target.deletedAt!=null)throw new ApiException(CommonCode.NOT_FOUND);
        target.adminLocked=locked;target.active=active;target.deactivatedAt=active?null:Instant.now();target.credentialRevision++;
        guard.verify(before);proofs.invalidateAll(targetId,Instant.now());sessions.revokeAll(targetId);
        audit.append(actorId,SecurityAudit.Event.USER_STATUS_CHANGED,Map.of("targetUserId",targetId));
        return view(target);
    }
    public java.util.Map<String,Object> deletionStatus(UUID target){
        var rows=jdbc.query("select state,attempts,requested_at,completed_at from account_deletions where user_id=?",(r,n)->{
            var result=new java.util.LinkedHashMap<String,Object>();result.put("state",r.getString("state"));result.put("attempts",r.getInt("attempts"));
            result.put("requestedAt",r.getTimestamp("requested_at").toInstant());result.put("completedAt",r.getTimestamp("completed_at")==null?null:r.getTimestamp("completed_at").toInstant());return result;
        },target);
        if(rows.isEmpty())throw new ApiException(CommonCode.NOT_FOUND);return rows.getFirst();
    }
    private UserView view(AppUser user){return new UserView(user.id,user.email,user.emailVerified,user.active,user.adminLocked,AccountStatus.of(user.active,user.adminLocked),Set.copyOf(user.roles));}
}
