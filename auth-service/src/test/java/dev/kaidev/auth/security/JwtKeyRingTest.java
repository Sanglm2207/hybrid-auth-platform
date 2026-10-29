package dev.kaidev.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import dev.kaidev.auth.config.AuthConfig;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.oauth2.jwt.*;

import static org.assertj.core.api.Assertions.*;

class JwtKeyRingTest {
    @TempDir Path directory;
    private Path manifest;
    private RSAKey oldKey, newKey;
    private JwtKeyRing ring;

    @BeforeEach void setup() throws Exception {
        oldKey = new RSAKeyGenerator(2048).keyID("old-key").generate();
        newKey = new RSAKeyGenerator(2048).keyID("new-key").generate();
        manifest = directory.resolve("manifest.json");
        write("old-key", oldKey);
        ring = new JwtKeyRing(manifest.toString(), "unused", "unused");
    }

    private void write(String active, RSAKey... keys) throws Exception {
        var value = new LinkedHashMap<String, Object>(new JWKSet(List.of(keys)).toJSONObject(false));
        value.put("activeKid", active);
        value.put("private-notes", "secret-manifest-metadata");
        Path temporary = directory.resolve("next.json");
        Files.writeString(temporary, new ObjectMapper().writeValueAsString(value));
        Files.move(temporary, manifest, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }
    private Jwt token() {
        Instant now = Instant.now();
        return ring.encode(JwtEncoderParameters.from(JwtClaimsSet.builder().issuer("http://issuer.test")
                .subject(UUID.randomUUID().toString()).audience(List.of("hybrid-api"))
                .issuedAt(now).expiresAt(now.plusSeconds(900)).build()));
    }

    @Test void stageAndActivateKeepsOldAndNewTokensValidAndPublishesOnlyPublicKeys() throws Exception {
        var decoder = new AuthConfig().jwtDecoder(ring, "http://issuer.test");
        Jwt old = token();
        write("old-key", oldKey, newKey); ring.reload();
        assertThat(ring.activeKid()).isEqualTo("old-key");
        assertThat(ring.publicKeys().getKeys()).hasSize(2);
        write("new-key", oldKey.toPublicJWK(), newKey); ring.reload();
        Jwt next = token();
        assertThat(next.getHeaders()).containsEntry("kid", "new-key");
        assertThat(decoder.decode(old.getTokenValue()).getSubject()).isEqualTo(old.getSubject());
        assertThat(decoder.decode(next.getTokenValue()).getSubject()).isEqualTo(next.getSubject());
        assertThat(ring.publicKeys().getKeys()).allMatch(key -> !key.isPrivate());
        assertThat(ring.publicKeys().toJSONObject()).containsOnlyKeys("keys");
        assertThat(ring.publicKeys().toString()).doesNotContain("secret-manifest-metadata");
    }

    @Test void invalidReloadAndPrematureRetirementRetainLastGoodSnapshot() throws Exception {
        token();
        write("new-key", oldKey, newKey); ring.reload();
        write("new-key", newKey); ring.reload();
        assertThat(ring.publicKeys().getKeys()).hasSize(2);
        Files.writeString(manifest, "invalid-private-content"); ring.reload();
        assertThat(ring.activeKid()).isEqualTo("new-key");
        assertThat(token().getHeaders()).containsEntry("kid", "new-key");
    }

    @Test void duplicateIdsMismatchedMaterialAndPublicOnlyActiveKeysCannotActivate() throws Exception {
        RSAKey replacement = new RSAKeyGenerator(2048).keyID("old-key").generate();
        write("old-key", replacement); ring.reload();
        assertThat(ring.publicKeys().getKeyByKeyId("old-key").toJSONString()).isEqualTo(oldKey.toPublicJWK().toJSONString());
        write("new-key", newKey.toPublicJWK()); ring.reload();
        assertThat(ring.activeKid()).isEqualTo("old-key");
        write("old-key", oldKey, replacement); ring.reload();
        assertThat(ring.publicKeys().getKeys()).hasSize(1);
        assertThat(token().getHeaders()).containsEntry("kid", "old-key");
    }

    @Test void concurrentIssuanceAndReloadNeverMixHeaderKidWithAnotherPrivateKey() throws Exception {
        write("old-key", oldKey, newKey); ring.reload();
        var decoder = new AuthConfig().jwtDecoder(ring, "http://issuer.test");
        try (var pool = Executors.newFixedThreadPool(8)) {
            List<Future<Jwt>> tokens = new ArrayList<>();
            for (int i = 0; i < 80; i++) {
                tokens.add(pool.submit(this::token));
                if (i % 10 == 0) { write(i % 20 == 0 ? "new-key" : "old-key", oldKey, newKey); ring.reload(); }
            }
            for (var issued : tokens) assertThat(decoder.decode(issued.get(10, TimeUnit.SECONDS).getTokenValue())).isNotNull();
        }
    }

    @Test void badInitialConfigurationFailsStartupRatherThanUsingAnUnintendedKey() throws Exception {
        Files.writeString(manifest, "{}");
        assertThatThrownBy(() -> new JwtKeyRing(manifest.toString(), "unused", "unused")).isInstanceOf(Exception.class);
    }
}
