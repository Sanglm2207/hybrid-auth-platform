package dev.kaidev.auth.service;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.dto.response.TokenResponse;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.security.SecurityState;
import dev.kaidev.auth.identity.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.ClientIdentity;
import dev.kaidev.common.security.SecurityAudit;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.stereotype.Service;

@Service
public class SessionService {
    private static final DefaultRedisScript<Long> ISSUE = SecurityState.script("session-issue");
    private static final DefaultRedisScript<Long> ROTATE = SecurityState.script("session-rotate");
    private static final DefaultRedisScript<Long> REVOKE = SecurityState.script("session-revoke");
    private static final DefaultRedisScript<Long> REVOKE_ID = SecurityState.script("session-revoke-id");
    private static final DefaultRedisScript<Long> REVOKE_ALL = SecurityState.script("session-revoke-all");
    private static final DefaultRedisScript<Long> VALID = SecurityState.script("session-valid");
    private static final ObjectMapper JSON = new ObjectMapper();
    private final dev.kaidev.auth.hardening.SessionLedger ledger;
    private final DeviceRegistry devices;
    private final String proxyKey;
    private final SecurityState state;
    private final JwtEncoder encoder;
    private final String issuer;
    private final long refreshTtl;
    private final SecureRandom random = new SecureRandom();

    public SessionService(SecurityState state, JwtEncoder encoder, String issuer, long refreshTtl) {
        this(state, encoder, issuer, refreshTtl, null, "", null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public SessionService(SecurityState state, JwtEncoder encoder, @Value("${app.issuer}") String issuer,
            @Value("${app.security.refresh-ttl-seconds:604800}") long refreshTtl, DeviceRegistry devices,
            @Value("${app.auth-proxy-key:}") String proxyKey, dev.kaidev.auth.hardening.SessionLedger ledger) {
        if (refreshTtl < 1 || refreshTtl > 604800) throw new IllegalArgumentException("Refresh TTL must be between 1 and 604800 seconds");
        this.state = state; this.encoder = encoder; this.issuer = issuer; this.refreshTtl = refreshTtl;
        this.devices = devices; this.proxyKey = proxyKey; this.ledger = ledger;
    }

    @org.springframework.transaction.annotation.Transactional
    public TokenResponse issue(AppUser user) {
        requireVerified(user);
        String family = UUID.randomUUID().toString();
        String epoch = ledger == null ? generation(user.id.toString()) : Long.toString(ledger.generation(user.id));
        if (ledger != null) state.execute(SecurityState.script("session-sync-generation"), List.of(versionKey(user.id.toString())), epoch);
        String refresh = newRefresh(), hash = ClientIdentity.hash(refresh);
        String metadata = user.id + "|" + family + "|" + epoch;
        DeviceInfo info = DeviceInfo.current(proxyKey, null);
        if (devices != null) devices.observe(user.id, info);
        if (ledger != null) ledger.create(user, UUID.fromString(family), hash, info, refreshTtl);
        long now = System.currentTimeMillis();
        var details = new SessionMetadata(user.id.toString(), Long.parseLong(epoch), user.credentialRevision, info.deviceId(), info.userAgent(),
                info.ip(), now, now, now + refreshTtl * 1000);
        TokenResponse response = response(user, family, refresh, epoch);
        long result = state.execute(ISSUE, List.of(tokenKey(hash), familyKey(family), versionKey(user.id.toString()), sessionKey(family), indexKey(user.id.toString()), state.key("user-cv:" + user.id)),
                epoch, metadata, Long.toString(refreshTtl), hash, json(details), family, Long.toString(now), Long.toString(user.credentialRevision), ledger == null ? "redis" : "sql");
        if (result == -2) throw new ApiException(AuthCode.SESSION_LIMIT_REACHED);
        if (result != 1) throw new ApiException(AuthCode.INVALID_REFRESH_TOKEN);
        return response;
    }

    @org.springframework.transaction.annotation.Transactional(noRollbackFor = dev.kaidev.auth.hardening.RefreshReuseException.class)
    public TokenResponse rotate(String token, UserRepository users) {
        String hash = ClientIdentity.hash(token);
        if (ledger != null) {
            UUID owner = ledger.owner(hash);
            if (owner == null) return invalidRefresh(null);
            AppUser account = users.findByIdForUpdate(owner).orElse(null);
            if (account == null || !account.active || account.adminLocked || account.deletedAt!=null || !account.emailVerified) return invalidRefresh(null);
            var status = ledger.inspect(account, hash);
            if (status == dev.kaidev.auth.hardening.SessionLedger.Rotation.USED) {
                audit(SecurityAudit.Event.REFRESH_REUSE, SecurityAudit.Outcome.DENIED, owner.toString());
                throw new dev.kaidev.auth.hardening.RefreshReuseException();
            }
            if (status != dev.kaidev.auth.hardening.SessionLedger.Rotation.ACTIVE) return invalidRefresh(owner.toString());
        }
        String metadata = state.get(tokenKey(hash));
        String[] parts = parse(metadata);
        if (parts == null) return invalidRefresh(null);
        AppUser user = users.findByIdForUpdate(UUID.fromString(parts[0])).orElse(null);
        if (user == null || !user.active || user.adminLocked || user.deletedAt!=null || !user.emailVerified) return invalidRefresh(parts[0]);
        String next = newRefresh(), nextHash = ClientIdentity.hash(next);
        // Sign before mutating Redis: a signing failure must not consume the client's token.
        SessionMetadata details = details(parts[1]);
        if (details == null || details.credentialRevision() != user.credentialRevision) return invalidRefresh(parts[0]);
        DeviceInfo info = DeviceInfo.current(proxyKey, details.deviceId());
        if (devices != null) devices.observe(user.id, info);
        TokenResponse response = response(user, parts[1], next, parts[2]);
        long result = state.execute(ROTATE, List.of(tokenKey(hash), tokenKey(nextHash), familyKey(parts[1]), versionKey(parts[0]), sessionKey(parts[1]), indexKey(parts[0])),
                metadata, parts[2], hash, nextHash, Long.toString(System.currentTimeMillis()), info.ip(), info.userAgent(), parts[1]);
        if (result == -1) {
            audit(SecurityAudit.Event.REFRESH_REUSE, SecurityAudit.Outcome.DENIED, parts[0]);
            if (ledger != null) {
                // Redis may be ahead after a previous SQL commit failure: persist this reuse denial too.
                ledger.revoke(user.id, UUID.fromString(parts[1]));
                throw new dev.kaidev.auth.hardening.RefreshReuseException();
            }
            throw new ApiException(AuthCode.INVALID_REFRESH_TOKEN);
        }
        if (result != 1) return invalidRefresh(parts[0]);
        if (ledger != null) ledger.consume(hash, nextHash, info);
        audit(SecurityAudit.Event.REFRESH, SecurityAudit.Outcome.SUCCESS, parts[0]);
        return response;
    }

    @org.springframework.transaction.annotation.Transactional
    public void revoke(String token) {
        if (ledger != null) {
            String hash = ClientIdentity.hash(token); UUID owner = ledger.owner(hash); UUID family = ledger.family(hash);
            if (owner != null && family != null) {
                try { ledger.revoke(owner, family); } catch (ApiException e) { if (e.apiCode() != AuthCode.SESSION_NOT_FOUND) throw e; }
            }
            audit(SecurityAudit.Event.LOGOUT, SecurityAudit.Outcome.SUCCESS, owner == null ? null : owner.toString()); return;
        }
        String hash = ClientIdentity.hash(token);
        String metadata = state.get(tokenKey(hash));
        String[] parts = parse(metadata);
        if (parts != null) state.execute(REVOKE, List.of(tokenKey(hash), familyKey(parts[1]), indexKey(parts[0])), metadata, parts[1]);
        audit(SecurityAudit.Event.LOGOUT, SecurityAudit.Outcome.SUCCESS, parts == null ? null : parts[0]);
    }

    @org.springframework.transaction.annotation.Transactional
    public void revokeAll(UUID userId) {
        if (ledger != null) { ledger.revokeAll(userId); audit(SecurityAudit.Event.LOGOUT_ALL, SecurityAudit.Outcome.SUCCESS, userId.toString()); return; }
        state.execute(REVOKE_ALL, List.of(versionKey(userId.toString()), indexKey(userId.toString())));
        audit(SecurityAudit.Event.LOGOUT_ALL, SecurityAudit.Outcome.SUCCESS, userId.toString());
    }

    public boolean active(UUID userId, UUID family, long generation) {
        SessionMetadata metadata = details(family.toString());
        return metadata != null && active(userId, family, generation, metadata.credentialRevision());
    }
    public boolean active(UUID userId, UUID family, long generation, long credentialRevision) {
        if (ledger != null) return ledger.active(userId, family, generation, credentialRevision);
        return state.execute(VALID, List.of(familyKey(family.toString()), sessionKey(family.toString()), versionKey(userId.toString())),
                userId.toString(), Long.toString(generation), Long.toString(System.currentTimeMillis()), Long.toString(credentialRevision)) == 1;
    }

    public List<SessionView> list(UUID userId, UUID current) {
        if (ledger != null) return ledger.list(userId, current);
        String owner = userId.toString(), epoch = generation(owner);
        List<SessionView> result = new ArrayList<>();
        for (String family : state.sessionIds(indexKey(owner))) {
            SessionMetadata metadata = details(family);
            String value = state.get(familyKey(family));
            if (metadata != null && metadata.userId().equals(owner) && Long.toString(metadata.generation()).equals(epoch)
                    && value != null && !value.equals("revoked") && metadata.expiresAt() > System.currentTimeMillis())
                result.add(new SessionView(UUID.fromString(family), metadata.deviceId(), metadata.userAgent(), metadata.ip(),
                        Instant.ofEpochMilli(metadata.createdAt()), Instant.ofEpochMilli(metadata.lastActivity()),
                        Instant.ofEpochMilli(metadata.expiresAt()), family.equals(current == null ? "" : current.toString())));
        }
        result.sort(Comparator.comparing(SessionView::lastActivityAt).reversed());
        return result;
    }

    @org.springframework.transaction.annotation.Transactional
    public void revokeSession(UUID owner, UUID family) {
        if (ledger != null) { ledger.revoke(owner, family); SecurityAudit.record(SecurityAudit.Event.SESSION_REVOKED, SecurityAudit.Outcome.SUCCESS, owner.toString(),MDC.get("traceId"),Map.of("targetUserId",owner,"sessionId",family)); return; }
        long result = state.execute(REVOKE_ID, List.of(familyKey(family.toString()), sessionKey(family.toString()),
                indexKey(owner.toString()), versionKey(owner.toString())), owner.toString(), family.toString());
        if (result != 1) throw new ApiException(AuthCode.SESSION_NOT_FOUND);
        audit(SecurityAudit.Event.SESSION_REVOKED, SecurityAudit.Outcome.SUCCESS, owner.toString());
    }

    private SessionMetadata details(String family) {
        String value = state.get(sessionKey(family));
        if (value == null) return null;
        try { return JSON.readValue(value, SessionMetadata.class); }
        catch (com.fasterxml.jackson.core.JsonProcessingException e) { throw new ApiException(AuthCode.SECURITY_UNAVAILABLE); }
    }
    private static String json(SessionMetadata details) {
        try { return JSON.writeValueAsString(details); }
        catch (com.fasterxml.jackson.core.JsonProcessingException e) { throw new IllegalStateException("Unable to encode session metadata"); }
    }
    private String sessionKey(String family) { return state.key("session:" + family); }
    private String indexKey(String userId) { return state.key("sessions:" + userId); }

    private TokenResponse response(AppUser user, String family, String refresh, String generation) {
        Instant now = Instant.now();
        var claims = JwtClaimsSet.builder().issuer(issuer).subject(user.id.toString()).audience(List.of("hybrid-api"))
                .issuedAt(now).expiresAt(now.plusSeconds(900)).id(UUID.randomUUID().toString())
                .claim("roles", user.roles.stream().sorted().toList()).claim("sid", family)
                .claim("cv", user.credentialRevision).claim("sv", Long.parseLong(generation)).build();
        String access = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims)).getTokenValue();
        return new TokenResponse(access, refresh, "Bearer", 900);
    }

    private TokenResponse invalidRefresh(String actor) {
        audit(SecurityAudit.Event.REFRESH, SecurityAudit.Outcome.DENIED, actor);
        throw new ApiException(AuthCode.INVALID_REFRESH_TOKEN);
    }
    private static void requireVerified(AppUser user) {
        if (!user.active || user.adminLocked || user.deletedAt!=null) throw new ApiException(AuthCode.ACCOUNT_DISABLED);
        if (!user.emailVerified) throw new ApiException(AuthCode.EMAIL_NOT_VERIFIED);
    }
    private static void audit(SecurityAudit.Event event, SecurityAudit.Outcome outcome, String actor) {
        SecurityAudit.record(event, outcome, actor, MDC.get("traceId"));
    }
    private String generation(String user) { String value = state.get(versionKey(user)); return value == null ? "0" : value; }
    private String tokenKey(String hash) { return state.key("token:" + hash); }
    private String familyKey(String family) { return state.key("family:" + family); }
    private String versionKey(String user) { return state.key("user-version:" + user); }
    private static String[] parse(String value) {
        if (value == null) return null;
        String[] parts = value.split("\\|", -1);
        if (parts.length != 3 || !parts[2].matches("[0-9]+")) return null;
        try { UUID.fromString(parts[0]); UUID.fromString(parts[1]); return parts; }
        catch (IllegalArgumentException e) { return null; }
    }
    private String newRefresh() {
        byte[] bytes = new byte[32]; random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
