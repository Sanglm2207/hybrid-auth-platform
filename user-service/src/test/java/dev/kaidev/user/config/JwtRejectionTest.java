package dev.kaidev.user.config;

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
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class JwtRejectionTest {
    @Test void realDecoderRejectsForgeryExpiryWrongIssuerAudienceAndUnsignedTokens() throws Exception {
        RSAKey trusted = new RSAKeyGenerator(2048).keyID("trusted").generate();
        RSAKey attacker = new RSAKeyGenerator(2048).keyID("trusted").generate();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/jwks", exchange -> {
            byte[] bytes = new JWKSet(trusted.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type","application/json");
            exchange.sendResponseHeaders(200,bytes.length);
            try(var output=exchange.getResponseBody()) { output.write(bytes); }
        });
        server.start();
        try {
            var decoder = new UserSecurity().decoder("http://127.0.0.1:"+server.getAddress().getPort()+"/jwks","http://issuer.test");
            var valid=claims("http://issuer.test","hybrid-api",900);
            assertThat(decoder.decode(sign(trusted,valid)).getSubject()).isEqualTo("11111111-1111-4111-8111-111111111111");
            for(String token:List.of(sign(attacker,valid),sign(trusted,claims("http://issuer.test","hybrid-api",-120)),
                    sign(trusted,claims("https://attacker.test","hybrid-api",900)),
                    sign(trusted,claims("http://issuer.test","another-api",900)),new PlainJWT(valid).serialize())) {
                assertThatThrownBy(()->decoder.decode(token)).isInstanceOf(org.springframework.security.oauth2.jwt.JwtException.class);
            }
        } finally { server.stop(0); }
    }
    private JWTClaimsSet claims(String issuer,String audience,long ttl) {
        return new JWTClaimsSet.Builder().issuer(issuer).subject("11111111-1111-4111-8111-111111111111")
                .audience(audience).issueTime(Date.from(Instant.now().minusSeconds(600)))
                .expirationTime(Date.from(Instant.now().plusSeconds(ttl))).build();
    }
    private String sign(RSAKey key,JWTClaimsSet claims) throws Exception {
        var jwt=new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),claims);
        jwt.sign(new RSASSASigner(key)); return jwt.serialize();
    }
}
