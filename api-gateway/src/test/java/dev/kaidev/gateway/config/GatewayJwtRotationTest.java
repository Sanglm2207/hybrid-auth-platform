package dev.kaidev.gateway.config;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.*;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class GatewayJwtRotationTest {
    @Test void remoteDecoderRefreshesOnNewKidAndKeepsOldTokensValid() throws Exception {
        RSAKey old = new RSAKeyGenerator(2048).keyID("old-key").generate();
        RSAKey next = new RSAKeyGenerator(2048).keyID("next-key").generate();
        var published = new AtomicReference<>(new JWKSet(old.toPublicJWK()).toString());
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/jwks", exchange -> {
            byte[] bytes = published.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (var output = exchange.getResponseBody()) { output.write(bytes); }
        });
        server.start();
        try {
            var decoder = new GatewaySecurity().decoder("http://127.0.0.1:" + server.getAddress().getPort() + "/jwks", "http://issuer.test");
            String oldToken = token(old);
            assertThat(decoder.decode(oldToken).block().getHeaders()).containsEntry("kid", "old-key");
            published.set(new JWKSet(List.of(old.toPublicJWK(), next.toPublicJWK())).toString());
            assertThat(decoder.decode(token(next)).block().getHeaders()).containsEntry("kid", "next-key");
            assertThat(decoder.decode(oldToken).block().getHeaders()).containsEntry("kid", "old-key");
        } finally { server.stop(0); }
    }

    private String token(RSAKey key) throws Exception {
        var claims = new JWTClaimsSet.Builder().issuer("http://issuer.test").subject(UUID.randomUUID().toString())
                .audience("hybrid-api").issueTime(new Date()).expirationTime(Date.from(Instant.now().plusSeconds(900))).build();
        var token = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        token.sign(new RSASSASigner(key)); return token.serialize();
    }
}
