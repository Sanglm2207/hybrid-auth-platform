package dev.kaidev.auth.service;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.dto.response.TokenResponse;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.common.exception.ApiException;

import java.time.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

@Service
public class SessionService {
    private final StringRedisTemplate redis;
    private final JwtEncoder encoder;
    private final String issuer;
    private final SecureRandom random = new SecureRandom();

    SessionService(StringRedisTemplate redis, JwtEncoder encoder, @Value("${app.issuer}") String issuer) {
        this.redis = redis;
        this.encoder = encoder;
        this.issuer = issuer;
    }

    public TokenResponse issue(AppUser user) {
        return issue(user, UUID.randomUUID().toString());
    }

    private TokenResponse issue(AppUser user, String family) {
        if (!user.emailVerified)
            throw new ApiException(AuthCode.EMAIL_NOT_VERIFIED);
        Instant now = Instant.now();
        String refresh = newRefresh();
        String hash = sha256(refresh);
        String value = user.id + "|" + user.role + "|" + family;
        redis.opsForValue().set("refresh:" + hash, value, Duration.ofDays(7));
        redis.opsForSet().add("family:" + family, hash);
        redis.expire("family:" + family, Duration.ofDays(7));
        JwtClaimsSet claims = JwtClaimsSet.builder().issuer(issuer).subject(user.id.toString())
                .audience(List.of("hybrid-api")).issuedAt(now).expiresAt(now.plusSeconds(900))
                .id(UUID.randomUUID().toString()).claim("roles", List.of(user.role)).claim("sid", family).build();
        String access = encoder.encode(
                JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).keyId("local-1").build(), claims))
                .getTokenValue();
        return new TokenResponse(access, refresh, "Bearer", 900);
    }

    public synchronized TokenResponse rotate(String token, UserRepository users) {
        String hash = sha256(token);
        String key = "refresh:" + hash;
        String value = redis.opsForValue().getAndDelete(key);
        if (value == null)
            throw new ApiException(AuthCode.INVALID_REFRESH_TOKEN);
        String[] parts = value.split("\\|");
        String family = parts[2];
        redis.opsForSet().remove("family:" + family, hash);
        AppUser user = users.findById(UUID.fromString(parts[0]))
                .orElseThrow(() -> new ApiException(AuthCode.INVALID_REFRESH_TOKEN));
        return issue(user, family);
    }

    public void revoke(String token) {
        String hash = sha256(token);
        String data = redis.opsForValue().get("refresh:" + hash);
        if (data == null)
            return;
        String[] parts = data.split("\\|");
        String family = parts[2];
        Set<String> hashes = redis.opsForSet().members("family:" + family);
        if (hashes != null)
            for (String h : hashes)
                redis.delete("refresh:" + h);
        redis.delete("family:" + family);
    }

    private String newRefresh() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String sha256(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(bytes);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
