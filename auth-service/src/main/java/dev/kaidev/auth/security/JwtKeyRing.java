package dev.kaidev.auth.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import dev.kaidev.common.security.ClientIdentity;
import dev.kaidev.common.security.SecurityAudit;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

/** Atomically replaces a validated key snapshot; bad reloads leave the last good snapshot active. */
@Component
public class JwtKeyRing implements JwtEncoder {
    private record Snapshot(RSAKey active, JWKSet publicKeys, String digest) {}
    private volatile Snapshot snapshot;
    private final Path manifest;
    private final Map<String, Instant> retainUntil = new HashMap<>();
    private final Map<String, String> knownKeys = new HashMap<>();

    public JwtKeyRing(@Value("${app.jwt.key-set:}") String manifest,
            @Value("${app.private-key}") String privatePath, @Value("${app.public-key}") String publicPath) throws Exception {
        this.manifest = manifest.isBlank() ? null : Path.of(manifest);
        if (this.manifest != null) load();
        else {
            var factory = KeyFactory.getInstance("RSA");
            var priv = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(pem(privatePath, "PRIVATE")));
            var pub = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(pem(publicPath, "PUBLIC")));
            RSAKey key = new RSAKey.Builder(pub).privateKey(priv).keyID("local-1").algorithm(JWSAlgorithm.RS256)
                    .keyUse(KeyUse.SIGNATURE).build();
            validate(key);
            snapshot = new Snapshot(key, new JWKSet(key.toPublicJWK()), "pem");
            knownKeys.put(key.getKeyID(), key.toPublicJWK().toJSONString());
        }
    }

    private static byte[] pem(String path, String type) throws Exception {
        return Base64.getDecoder().decode(Files.readString(Path.of(path))
                .replace("-----BEGIN " + type + " KEY-----", "").replace("-----END " + type + " KEY-----", "").replaceAll("\\s", ""));
    }

    @Override public synchronized Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
        Snapshot current = snapshot;
        var header = JwsHeader.with(SignatureAlgorithm.RS256).type("JWT").keyId(current.active().getKeyID()).build();
        var encoder = new NimbusJwtEncoder((selector, context) -> selector.select(new JWKSet(current.active())));
        Jwt jwt = encoder.encode(JwtEncoderParameters.from(header, parameters.getClaims()));
        Instant expires = jwt.getExpiresAt();
        if (expires != null) retainUntil.merge(current.active().getKeyID(), expires.plusSeconds(60),
                (a, b) -> a.isAfter(b) ? a : b);
        return jwt;
    }

    public JWKSet publicKeys() { return snapshot.publicKeys(); }
    public String activeKid() { return snapshot.active().getKeyID(); }

    @Scheduled(fixedDelayString = "${app.jwt.reload-ms:5000}")
    public synchronized void reload() {
        if (manifest == null) return;
        try { load(); }
        catch (Exception e) {
            // Never log the manifest, private material, path, or parse error contents.
            SecurityAudit.record(SecurityAudit.Event.JWT_KEYS_RELOADED, SecurityAudit.Outcome.FAILURE, null, MDC.get("correlationId"));
        }
    }

    private void load() throws Exception {
        String json = Files.readString(manifest);
        String digest = ClientIdentity.hash(json);
        if (snapshot != null && snapshot.digest().equals(digest)) return;
        String kid = new ObjectMapper().readTree(json).path("activeKid").asText();
        JWKSet set = JWKSet.parse(json);
        if (set.getKeys().isEmpty()) throw new IllegalArgumentException("No JWT keys configured");
        Set<String> ids = new HashSet<>();
        for (JWK entry : set.getKeys()) {
            if (!(entry instanceof RSAKey rsa) || !ids.add(entry.getKeyID()))
                throw new IllegalArgumentException("JWT keys must be unique RSA keys");
            validate(rsa);
            String previous = knownKeys.get(rsa.getKeyID());
            if (previous != null && !previous.equals(rsa.toPublicJWK().toJSONString()))
                throw new IllegalArgumentException("Never reuse a kid for different key material");
        }
        RSAKey active = set.getKeyByKeyId(kid) instanceof RSAKey rsa ? rsa : null;
        if (active == null || !active.isPrivate()) throw new IllegalArgumentException("Active signing key requires private material");
        Instant now = Instant.now();
        for (var entry : retainUntil.entrySet()) {
            if (entry.getValue().isAfter(now) && !ids.contains(entry.getKey()))
                throw new IllegalArgumentException("Retain verification keys until issued JWTs expire");
        }
        // Check that the active private parameters actually match its public key before publishing it.
        Signature proof = Signature.getInstance("SHA256withRSA");
        byte[] challenge = "key-validation".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        proof.initSign(active.toRSAPrivateKey()); proof.update(challenge); byte[] signed = proof.sign();
        proof.initVerify(active.toRSAPublicKey()); proof.update(challenge);
        if (!proof.verify(signed)) throw new IllegalArgumentException("JWT key pair does not match");
        // Rebuild rather than copying custom manifest members into the public JWKS response.
        snapshot = new Snapshot(active, new JWKSet(set.getKeys().stream().map(JWK::toPublicJWK).toList()), digest);
        for (JWK entry : set.getKeys()) knownKeys.put(entry.getKeyID(), entry.toPublicJWK().toJSONString());
        retainUntil.entrySet().removeIf(e -> !e.getValue().isAfter(now));
        SecurityAudit.record(SecurityAudit.Event.JWT_KEYS_RELOADED, SecurityAudit.Outcome.SUCCESS, null, MDC.get("correlationId"));
    }

    private static void validate(RSAKey key) throws Exception {
        if (key.getKeyID() == null || !key.getKeyID().matches("[A-Za-z0-9._-]{1,80}") || key.size() < 2048
                || (key.getAlgorithm() != null && !JWSAlgorithm.RS256.equals(key.getAlgorithm()))
                || (key.getKeyUse() != null && !KeyUse.SIGNATURE.equals(key.getKeyUse())))
            throw new IllegalArgumentException("JWT keys require a valid kid, RSA >=2048, RS256 and signature use");
        key.toRSAPublicKey();
    }
}
