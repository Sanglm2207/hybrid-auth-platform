package dev.kaidev.gateway.integration;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import static org.assertj.core.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.auth-proxy-key=p6-test-proxy-key-at-least-thirty-two-characters",
        "spring.cloud.gateway.server.webflux.httpclient.response-timeout=250ms"})
class GatewayResilienceTest {
    static HttpServer upstream;
    static ExecutorService executor;
    static final AtomicInteger rotations = new AtomicInteger();
    static final AtomicBoolean slow = new AtomicBoolean();
    @Autowired WebTestClient client;
    @MockitoBean ReactiveJwtDecoder decoder;

    @DynamicPropertySource static void upstream(DynamicPropertyRegistry properties) throws Exception {
        upstream = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        executor = Executors.newCachedThreadPool(); upstream.setExecutor(executor);
        upstream.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            rotations.incrementAndGet(); // Simulate rotation committed before response is lost.
            if (slow.get()) {
                try { Thread.sleep(700); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                try { exchange.sendResponseHeaders(200, -1); } catch (java.io.IOException ignored) { }
            }
            // Immediate close simulates a TCP abort after a write has committed.
            exchange.close();
        });
        upstream.start();
        properties.add("AUTH_URL", () -> "http://127.0.0.1:" + upstream.getAddress().getPort());
    }
    @AfterAll static void stop() { upstream.stop(0); executor.shutdownNow(); }

    @Test void refreshIsForwardedExactlyOnceOnTimeoutAndTcpAbort() {
        slow.set(true);
        client.post().uri("/api/v1/auth/refresh").bodyValue(java.util.Map.of("refreshToken", "test-token"))
                .exchange().expectStatus().isEqualTo(504).expectHeader().valueEquals("X-Refresh-Outcome", "unknown")
                .expectBody().jsonPath("$.code").isEqualTo("UPSTREAM_TIMEOUT");
        assertThat(rotations).hasValue(1);
        slow.set(false);
        client.post().uri("/api/v1/auth/refresh").bodyValue(java.util.Map.of("refreshToken", "test-token"))
                .exchange().expectStatus().isEqualTo(502).expectHeader().valueEquals("X-Refresh-Outcome", "unknown");
        assertThat(rotations).hasValue(2);
        for (int i = 0; i < 3; i++) client.post().uri("/api/v1/auth/refresh")
                .bodyValue(java.util.Map.of("refreshToken", "test-token"))
                .exchange().expectStatus().isEqualTo(502);
        client.post().uri("/api/v1/auth/refresh").bodyValue(java.util.Map.of("refreshToken", "test-token"))
                .exchange().expectStatus().isEqualTo(503).expectHeader().doesNotExist("X-Refresh-Outcome");
        assertThat(rotations).hasValue(5);
    }

    @Test void probesArePublicAndLivenessDoesNotDependOnUpstream() {
        client.get().uri("/actuator/health/liveness").exchange().expectStatus().isOk();
        client.get().uri("/actuator/health/readiness").exchange().expectStatus().isOk();
        client.get().uri("/actuator/env").exchange().expectStatus().isUnauthorized();
    }
}
