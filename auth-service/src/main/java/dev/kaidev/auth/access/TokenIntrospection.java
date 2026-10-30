package dev.kaidev.auth.access;

import dev.kaidev.auth.identity.IdentityValidationService;
import dev.kaidev.common.security.*;
import java.time.Instant;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TokenIntrospection {
    private final dev.kaidev.auth.security.SecurityState state;
    private final JwtDecoder decoder;private final IdentityValidationService identities;private final JdbcTemplate jdbc;
    public TokenIntrospection(JwtDecoder decoder,IdentityValidationService identities,JdbcTemplate jdbc,dev.kaidev.auth.security.SecurityState state){this.decoder=decoder;this.identities=identities;this.jdbc=jdbc;this.state=state;}
    @Transactional public Map<String,Object> inspect(UUID caller,String token){
        if(token.matches("[A-Za-z0-9_-]{43}")) {
            var rows=jdbc.query("select r.user_id,r.session_id,r.consumed_at,r.expires_at,s.generation,s.credential_revision from identity_refresh_ledger r join identity_sessions s on s.id=r.session_id where r.token_hash=?",
                    (r,n)->{
                        if(!caller.equals(r.getObject("user_id",UUID.class))||r.getTimestamp("consumed_at")!=null||!r.getTimestamp("expires_at").toInstant().isAfter(Instant.now())
                                ||state.get(state.key("token:"+ClientIdentity.hash(token)))==null)return Map.<String,Object>of("active",false);
                        var check=new IdentityCheck(caller,r.getObject("session_id",UUID.class),r.getLong("generation"),r.getLong("credential_revision"));
                        return identities.check(check).active()?Map.<String,Object>of("active",true,"tokenType","refresh_token","sessionId",check.sessionId(),"expiresAt",r.getTimestamp("expires_at").toInstant()):Map.<String,Object>of("active",false);
                    },ClientIdentity.hash(token));
            return rows.isEmpty()?Map.of("active",false):rows.getFirst();
        }
        try{
            var jwt=decoder.decode(token);if(jwt.getExpiresAt()==null)return Map.of("active",false);var check=IdentityCheck.fromClaims(jwt.getClaims());
            if(!check.subject().equals(caller))return Map.of("active",false);
            var access=identities.check(check);if(!access.active())return Map.of("active",false);
            return Map.of("active",true,"tokenType","access_token","subject",caller,"sessionId",check.sessionId(),"expiresAt",jwt.getExpiresAt(),"permissions",access.permissions());
        }catch(JwtException|IllegalArgumentException e){return Map.of("active",false);}
    }
}
