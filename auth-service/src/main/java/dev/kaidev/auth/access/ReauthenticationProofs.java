package dev.kaidev.auth.access;

import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.ClientIdentity;
import dev.kaidev.common.security.IdentityCheck;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.*;

/** Short-lived proof bound to the authenticated subject, session and credential generations. */
@Service
public class ReauthenticationProofs {
    public static final String HEADER="X-Reauthentication-Token";
    public record Issued(String reauthenticationToken,Instant expiresAt,long expiresIn) {
        @Override public String toString(){return "ReauthenticationProof[REDACTED]";}
    }
    private final JdbcTemplate jdbc;
    public ReauthenticationProofs(JdbcTemplate jdbc){this.jdbc=jdbc;}
    public Issued issue(AppUser owner){
        var identity=current(owner);byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);
        String raw=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);Instant expires=Instant.now().plusSeconds(300);
        jdbc.update("delete from reauthentication_proofs where user_id=? and (session_id=? or expires_at<=CURRENT_TIMESTAMP)",owner.id,identity.sessionId());
        jdbc.update("insert into reauthentication_proofs(proof_hash,user_id,session_id,credential_revision,session_generation,expires_at) values(?,?,?,?,?,?)",
                ClientIdentity.hash(raw),owner.id,identity.sessionId(),owner.credentialRevision,owner.sessionGeneration,Timestamp.from(expires));
        return new Issued(raw,expires,300);
    }
    public boolean valid(AppUser owner){
        if(!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes))return false;
        var values=Collections.list(attributes.getRequest().getHeaders(HEADER));
        if(values.size()!=1||!values.getFirst().matches("[A-Za-z0-9_-]{43}"))return false;
        var identity=current(owner);
        return jdbc.queryForObject("select count(*) from reauthentication_proofs where proof_hash=? and user_id=? and session_id=? and credential_revision=? and session_generation=? and expires_at>CURRENT_TIMESTAMP",
                Long.class,ClientIdentity.hash(values.getFirst()),owner.id,identity.sessionId(),owner.credentialRevision,owner.sessionGeneration)==1;
    }
    private IdentityCheck current(AppUser owner){
        var authentication=SecurityContextHolder.getContext().getAuthentication();
        if(authentication instanceof JwtAuthenticationToken jwt && authentication.isAuthenticated()){
            var identity=IdentityCheck.fromClaims(jwt.getToken().getClaims());
            if(identity.subject().equals(owner.id)&&identity.credentialRevision()==owner.credentialRevision&&identity.sessionVersion()==owner.sessionGeneration)return identity;
        }
        throw new ApiException(CommonCode.UNAUTHENTICATED);
    }
}
