package dev.kaidev.gateway.filter;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.*;

class GatewayIdentityFilterTest {
    @Test void livePermissionsAreInstalledExactlyOnceAndRevokedStateIsDenied() throws Exception {
        var active = new AtomicBoolean(true); var calls = new AtomicInteger();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/internal/identity/check", request -> {
            request.getRequestBody().readAllBytes(); calls.incrementAndGet();
            String body = "{\"success\":true,\"data\":{\"active\":"+active.get()+",\"roles\":[\"USER\"],\"permissions\":[\"profile:read\"]}}";
            byte[] bytes=body.getBytes(StandardCharsets.UTF_8); request.getResponseHeaders().set("Content-Type","application/json");
            request.sendResponseHeaders(200,bytes.length); try(var output=request.getResponseBody()){output.write(bytes);}
        }); server.start();
        try {
            var filter = new GatewayIdentityFilter("http://127.0.0.1:"+server.getAddress().getPort(),"identity-key-at-least-thirty-two-characters",
                    JsonMapper.builder().addModule(new JavaTimeModule()).build());
            var jwt=Jwt.withTokenValue("test-token").header("alg","RS256").subject(UUID.randomUUID().toString())
                    .claim("sid",UUID.randomUUID().toString()).claim("sv",0L).claim("cv",0L).build();
            var authentication=new JwtAuthenticationToken(jwt); var passed=new AtomicInteger();
            var exchange=MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost/api/v1/users/me"));
            filter.filter(exchange.mutate().principal(Mono.just(authentication)).build(), next -> {
                passed.incrementAndGet(); return next.getPrincipal().cast(JwtAuthenticationToken.class).doOnNext(token ->
                        assertThat(token.getAuthorities()).anyMatch(a -> a.getAuthority().equals("profile:read"))).then();
            }).block();
            assertThat(passed.get()).isEqualTo(1); active.set(false);
            var denied=MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost/api/v1/users/me"));
            filter.filter(denied.mutate().principal(Mono.just(authentication)).build(), next -> { passed.incrementAndGet(); return Mono.empty(); }).block();
            assertThat(denied.getResponse().getStatusCode().value()).isEqualTo(401); assertThat(passed.get()).isEqualTo(1); assertThat(calls.get()).isEqualTo(2);
        } finally { server.stop(0); }
    }
    @Test void missingIdentityKeyFailsClosedForAuthenticatedRequests() {
        var exchange=MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost/api/v1/users/me"));
        var jwt=Jwt.withTokenValue("token").header("alg","RS256").subject(UUID.randomUUID().toString()).build();
        new GatewayIdentityFilter("http://127.0.0.1:1","",JsonMapper.builder().addModule(new JavaTimeModule()).build())
                .filter(exchange.mutate().principal(Mono.just(new JwtAuthenticationToken(jwt))).build(), next -> Mono.error(new AssertionError("Must not forward"))).block();
        assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(503);
    }
}
