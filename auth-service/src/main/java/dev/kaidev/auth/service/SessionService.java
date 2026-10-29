package dev.kaidev.auth.service;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.dto.response.TokenResponse;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.security.SecurityState;
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
    private final SecurityState state;
    private final JwtEncoder encoder;
    private final String issuer;
    private final long refreshTtl;
    private final SecureRandom random = new SecureRandom();

    public SessionService(SecurityState state, JwtEncoder encoder, @Value("${app.issuer}") String issuer,
            @Value("${app.security.refresh-ttl-seconds:604800}") long refreshTtl) {
        if (refreshTtl < 1 || refreshTtl > 604800) throw new IllegalArgumentException("Refresh TTL must be between 1 and 604800 seconds");
        this.state = state; this.encoder = encoder; this.issuer = issuer; this.refreshTtl = refreshTtl;
    }

    public TokenResponse issue(AppUser user) {
        requireVerified(user);
        String family = UUID.randomUUID().toString();
        String epoch = generation(user.id.toString());
        String refresh = newRefresh(), hash = ClientIdentity.hash(refresh);
        String metadata = user.id + "|" + family + "|" + epoch;
        TokenResponse response = response(user, family, refresh);
        long result = state.execute(ISSUE, List.of(tokenKey(hash), familyKey(family), versionKey(user.id.toString())),
                epoch, metadata, Long.toString(refreshTtl), hash);
        if (result != 1) throw new ApiException(AuthCode.INVALID_REFRESH_TOKEN);
        return response;
    }

    @org.springframework.transaction.annotation.Transactional
    public TokenResponse rotate(String token, UserRepository users) {
        String hash = ClientIdentity.hash(token);
        String metadata = state.get(tokenKey(hash));
        String[] parts = parse(metadata);
        if (parts == null) return invalidRefresh(null);
        AppUser user = users.findByIdForUpdate(UUID.fromString(parts[0])).orElse(null);
        if (user == null || !user.emailVerified) return invalidRefresh(parts[0]);
        String next = newRefresh(), nextHash = ClientIdentity.hash(next);
        // Sign before mutating Redis: a signing failure must not consume the client's token.
        TokenResponse response = response(user, parts[1], next);
        long result = state.execute(ROTATE, List.of(tokenKey(hash), tokenKey(nextHash), familyKey(parts[1]), versionKey(parts[0])),
                metadata, parts[2], hash, nextHash);
        if (result == -1) {
            audit(SecurityAudit.Event.REFRESH_REUSE, SecurityAudit.Outcome.DENIED, parts[0]);
            throw new ApiException(AuthCode.INVALID_REFRESH_TOKEN);
        }
        if (result != 1) return invalidRefresh(parts[0]);
        audit(SecurityAudit.Event.REFRESH, SecurityAudit.Outcome.SUCCESS, parts[0]);
        return response;
    }

    public void revoke(String token) {
        String hash = ClientIdentity.hash(token);
        String metadata = state.get(tokenKey(hash));
        String[] parts = parse(metadata);
        if (parts != null) state.execute(REVOKE, List.of(tokenKey(hash), familyKey(parts[1])), metadata);
        audit(SecurityAudit.Event.LOGOUT, SecurityAudit.Outcome.SUCCESS, parts == null ? null : parts[0]);
    }

    public void revokeAll(UUID userId) {
        state.increment(versionKey(userId.toString()));
        audit(SecurityAudit.Event.LOGOUT_ALL, SecurityAudit.Outcome.SUCCESS, userId.toString());
    }

    private TokenResponse response(AppUser user, String family, String refresh) {
        Instant now = Instant.now();
        var claims = JwtClaimsSet.builder().issuer(issuer).subject(user.id.toString()).audience(List.of("hybrid-api"))
                .issuedAt(now).expiresAt(now.plusSeconds(900)).id(UUID.randomUUID().toString())
                .claim("roles", List.of(user.role)).claim("sid", family).build();
        String access = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims)).getTokenValue();
        return new TokenResponse(access, refresh, "Bearer", 900);
    }

    private TokenResponse invalidRefresh(String actor) {
        audit(SecurityAudit.Event.REFRESH, SecurityAudit.Outcome.DENIED, actor);
        throw new ApiException(AuthCode.INVALID_REFRESH_TOKEN);
    }
    private static void requireVerified(AppUser user) {
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
