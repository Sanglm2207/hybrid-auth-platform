package dev.kaidev.auth.hardening;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.identity.*;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.common.exception.ApiException;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service @Transactional
public class SessionLedger {
    public enum Rotation { ACTIVE, USED, INACTIVE }
    private final AuthAuditStore audit;
    private final DurableSessionRepository sessions; private final DurableRefreshRepository refresh; private final UserRepository users;
    public SessionLedger(DurableSessionRepository sessions, DurableRefreshRepository refresh, UserRepository users,AuthAuditStore audit){this.audit=audit;this.sessions=sessions;this.refresh=refresh;this.users=users;}
    public long generation(UUID user){return users.findByIdForUpdate(user).orElseThrow().sessionGeneration;}
    public UUID owner(String hash){return refresh.owner(hash).orElse(null);}
    public UUID family(String hash){return refresh.findById(hash).map(r->r.sessionId).orElse(null);}
    public Rotation inspect(AppUser user,String hash){
        var token=refresh.findById(hash).orElse(null); if(token==null)return Rotation.INACTIVE;
        var session=sessions.findById(token.sessionId).orElse(null);
        if(session==null || !session.userId.equals(user.id) || session.revokedAt!=null || !Instant.now().isBefore(session.expiresAt)
                || session.generation!=user.sessionGeneration || session.credentialRevision!=user.credentialRevision)return Rotation.INACTIVE;
        if(token.consumedAt!=null || !hash.equals(session.currentHash)){session.revokedAt=Instant.now();audit.append(user.id,dev.kaidev.common.security.SecurityAudit.Event.REFRESH_REUSE,Map.of("targetUserId",user.id,"sessionId",session.id));return Rotation.USED;}
        return Rotation.ACTIVE;
    }
    public void create(AppUser user,UUID family,String hash,DeviceInfo info,long ttl){
        long count=list(user.id,null).size(); if(count>=100)throw new ApiException(AuthCode.SESSION_LIMIT_REACHED);
        var s=new DurableSession(); s.id=family;s.userId=user.id;s.generation=user.sessionGeneration;s.credentialRevision=user.credentialRevision;
        s.currentHash=hash;s.deviceId=info.deviceId();s.ip=info.ip();s.userAgent=info.userAgent();s.createdAt=Instant.now();s.lastActivityAt=s.createdAt;s.expiresAt=s.createdAt.plusSeconds(ttl);
        sessions.saveAndFlush(s); addToken(user.id,family,hash,s.expiresAt);
    }
    public void consume(String oldHash,String nextHash,DeviceInfo info){
        var old=refresh.findById(oldHash).orElseThrow();var s=sessions.findById(old.sessionId).orElseThrow();
        old.consumedAt=Instant.now();s.currentHash=nextHash;s.lastActivityAt=Instant.now();s.ip=info.ip();s.userAgent=info.userAgent();addToken(s.userId,s.id,nextHash,s.expiresAt);
    }
    private void addToken(UUID user,UUID family,String hash,Instant expires){var r=new DurableRefresh();r.tokenHash=hash;r.userId=user;r.sessionId=family;r.expiresAt=expires;refresh.save(r);}
    public void revoke(UUID user,UUID family){
        users.findByIdForUpdate(user).orElseThrow();var s=sessions.findById(family).orElse(null);
        if(s==null || !s.userId.equals(user) || s.revokedAt!=null || !Instant.now().isBefore(s.expiresAt))throw new ApiException(AuthCode.SESSION_NOT_FOUND);
        s.revokedAt=Instant.now();audit.append(user,dev.kaidev.common.security.SecurityAudit.Event.SESSION_REVOKED,Map.of("targetUserId",user,"sessionId",family));
    }
    public void revokeAll(UUID user){var owner=users.findByIdForUpdate(user).orElseThrow();owner.sessionGeneration++;sessions.revokeAll(user,Instant.now());audit.append(user,dev.kaidev.common.security.SecurityAudit.Event.LOGOUT_ALL,Map.of("targetUserId",user));}
    public boolean active(UUID user,UUID family,long generation,long revision){
        var owner=users.findById(user).orElse(null);var s=sessions.findById(family).orElse(null);
        boolean valid=owner!=null && owner.active && !owner.adminLocked && owner.deletedAt==null && owner.emailVerified && owner.sessionGeneration==generation && owner.credentialRevision==revision
                && s!=null && s.userId.equals(user) && s.generation==generation && s.credentialRevision==revision
                && s.revokedAt==null && Instant.now().isBefore(s.expiresAt);
        Instant now=Instant.now();
        if(valid && s.lastActivityAt.isBefore(now.minusSeconds(30))) sessions.touch(family,now,now.minusSeconds(30));
        return valid;
    }
    @Transactional(readOnly=true)
    public List<SessionView> list(UUID user,UUID current){
        var owner=users.findById(user).orElseThrow();
        return sessions.findByUserIdAndRevokedAtIsNullAndExpiresAtAfter(user,Instant.now()).stream()
                .filter(s->s.generation==owner.sessionGeneration && s.credentialRevision==owner.credentialRevision)
                .sorted(Comparator.comparing((DurableSession s)->s.lastActivityAt).reversed())
                .map(s->new SessionView(s.id,s.deviceId,s.userAgent,s.ip,s.createdAt,s.lastActivityAt,s.expiresAt,s.id.equals(current))).toList();
    }
}
