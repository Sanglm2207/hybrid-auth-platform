package dev.kaidev.auth.access;

import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.hardening.AuthAuditStore;
import dev.kaidev.auth.identity.RolePolicyService;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.*;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Named machine credentials are bound to one owner; live scopes can never exceed that owner's grants. */
@Service
public class ServiceCredentials {
    public static final Set<String> ALLOWED=Set.of("profile:read","profile:write","users:read","users:update");
    public record KeyView(UUID id,String name,Set<String> scopes,Instant createdAt,Instant expiresAt,Instant revokedAt,Instant lastUsedAt) {}
    public record Issued(KeyView key,String secret) { @Override public String toString(){return "IssuedApiKey[REDACTED]";} }
    public record MachineToken(String accessToken,String tokenType,long expiresIn,Set<String> scopes) {
        @Override public String toString(){return "MachineToken[REDACTED]";}
    }
    private record Credential(KeyView view,UUID owner,String hash,long revision,long generation) {}
    private final JdbcTemplate jdbc;private final ActorSecurity security;private final RolePolicyService roles;
    private final UserRepository users;private final JwtEncoder encoder;private final String issuer;private final AuthAuditStore audit;
    public ServiceCredentials(JdbcTemplate jdbc,ActorSecurity security,RolePolicyService roles,UserRepository users,
            JwtEncoder encoder,@Value("${app.issuer}")String issuer,AuthAuditStore audit){
        this.jdbc=jdbc;this.security=security;this.roles=roles;this.users=users;this.encoder=encoder;this.issuer=issuer;this.audit=audit;
    }
    @Transactional
    public Issued create(UUID owner,String name,Set<String> scopes,Instant expires,String password){
        var user=security.lock(owner);security.require(user,"keys:manage");security.reauthenticate(user,password);
        var now=Instant.now();
        if(name==null||name.isBlank()||name.length()>100||scopes==null||scopes.isEmpty()||!ALLOWED.containsAll(scopes)
                ||!roles.permissions(user.roles).containsAll(scopes)||expires==null||!expires.isAfter(now)||expires.isAfter(now.plusSeconds(365L*86400)))
            throw new ApiException(CommonCode.INVALID_REQUEST);
        if(jdbc.queryForObject("select count(*) from identity_api_keys where user_id=? and revoked_at is null and expires_at>?",Long.class,owner,Timestamp.from(now))>=20)
            throw new ApiException(CommonCode.CONFLICT);
        byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);String raw="hap_"+Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        UUID id=UUID.randomUUID();
        jdbc.update("insert into identity_api_keys(id,user_id,name,secret_hash,scopes,created_at,expires_at,credential_revision,session_generation) values(?,?,?,?,?,?,?,?,?)",
                id,owner,name,ClientIdentity.hash(raw),String.join(" ",new TreeSet<>(scopes)),Timestamp.from(now),Timestamp.from(expires),user.credentialRevision,user.sessionGeneration);
        audit.append(owner,SecurityAudit.Event.API_KEY_CREATED,Map.of("targetUserId",owner));
        return new Issued(new KeyView(id,name,Set.copyOf(scopes),now,expires,null,null),raw);
    }
    public List<KeyView> list(UUID owner){return credentials("user_id=?",owner).stream().map(Credential::view).toList();}
    @Transactional public void revoke(UUID owner,UUID id){
        security.require(security.lock(owner),"keys:manage");
        if(jdbc.update("update identity_api_keys set revoked_at=COALESCE(revoked_at,?) where id=? and user_id=?",Timestamp.from(Instant.now()),id,owner)!=1)
            throw new ApiException(CommonCode.NOT_FOUND);
        audit.append(owner,SecurityAudit.Event.API_KEY_REVOKED,Map.of("targetUserId",owner));
    }
    @Transactional public MachineToken exchange(String raw){
        if(raw==null||!raw.matches("hap_[A-Za-z0-9_-]{43}"))throw new ApiException(CommonCode.UNAUTHENTICATED);
        var found=credentials("secret_hash=?",ClientIdentity.hash(raw));
        if(found.isEmpty())throw new ApiException(CommonCode.UNAUTHENTICATED);
        var credential=found.getFirst(); var user=security.lock(credential.owner());
        var access=access(user,credential);if(!access.active())throw new ApiException(CommonCode.UNAUTHENTICATED);
        var now=Instant.now();long ttl=Math.min(300,credential.view().expiresAt().getEpochSecond()-now.getEpochSecond());
        if(ttl<1)throw new ApiException(CommonCode.UNAUTHENTICATED);
        var claims=JwtClaimsSet.builder().issuer(issuer).subject(user.id.toString()).audience(List.of("hybrid-api"))
                .issuedAt(now).expiresAt(now.plusSeconds(ttl)).claim("sid",credential.view().id().toString())
                .claim("cv",user.credentialRevision).claim("sv",user.sessionGeneration).claim("machine",true).build();
        String token=encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        jdbc.update("update identity_api_keys set last_used_at=? where id=?",Timestamp.from(now),credential.view().id());
        return new MachineToken(token,"Bearer",ttl,access.permissions());
    }
    public Optional<IdentityAccess> check(AppUser owner,IdentityCheck request){
        var found=credentials("id=?",request.sessionId());if(found.isEmpty())return Optional.empty();
        var credential=found.getFirst();
        if(!credential.owner().equals(owner.id)||request.sessionVersion()!=owner.sessionGeneration||request.credentialRevision()!=owner.credentialRevision)
            return Optional.of(IdentityAccess.denied());
        return Optional.of(access(owner,credential));
    }
    private IdentityAccess access(AppUser owner,Credential c){
        if(!owner.active||owner.adminLocked||!owner.emailVerified||owner.deletedAt!=null||c.view().revokedAt()!=null
                ||!Instant.now().isBefore(c.view().expiresAt())||c.revision()!=owner.credentialRevision||c.generation()!=owner.sessionGeneration)return IdentityAccess.denied();
        var grants=new HashSet<>(c.view().scopes());grants.retainAll(roles.permissions(owner.roles));
        return new IdentityAccess(true,Set.of(),Set.copyOf(grants));
    }
    private List<Credential> credentials(String condition,Object value){
        return jdbc.query("select * from identity_api_keys where "+condition+" order by created_at desc",(r,n)->new Credential(
                new KeyView(r.getObject("id",UUID.class),r.getString("name"),Set.of(r.getString("scopes").split(" ")),r.getTimestamp("created_at").toInstant(),r.getTimestamp("expires_at").toInstant(),
                        r.getTimestamp("revoked_at")==null?null:r.getTimestamp("revoked_at").toInstant(),r.getTimestamp("last_used_at")==null?null:r.getTimestamp("last_used_at").toInstant()),
                r.getObject("user_id",UUID.class),r.getString("secret_hash"),r.getLong("credential_revision"),r.getLong("session_generation")),value);
    }
}
