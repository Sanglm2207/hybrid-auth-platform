package dev.kaidev.gateway.integration;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "app.gateway.allowed-hosts=localhost,127.0.0.1,[::1]",
        "app.gateway.allowed-origins=https://client.example.com",
        "app.gateway.require-origin=false",
        "app.auth-proxy-key=test-proxy-key-at-least-thirty-two-characters",
        "AUTH_URL=http://127.0.0.1:1"})
@org.junit.jupiter.api.TestMethodOrder(org.junit.jupiter.api.MethodOrderer.OrderAnnotation.class)
class GatewayAccessTest {
    @Autowired WebTestClient client;
    @MockitoBean ReactiveJwtDecoder decoder;

    @BeforeEach void setup() {
        when(decoder.decode(anyString())).thenReturn(Mono.error(new BadJwtException("invalid test token")));
    }

    @Test void rejectsUnknownHostWithEnvelope() {
        client.get().uri("/actuator/health").header(HttpHeaders.HOST, "evil.example.com")
                .exchange().expectStatus().isForbidden().expectBody()
                .jsonPath("$.code").isEqualTo("HOST_NOT_ALLOWED").jsonPath("$.success").isEqualTo(false)
                .jsonPath("$.traceId").isNotEmpty();
    }

    @Test void forwardedHostCannotBypassAllowlist() {
        client.get().uri("/actuator/health").header(HttpHeaders.HOST, "evil.example.com")
                .header("X-Forwarded-Host", "localhost").header("Forwarded", "host=localhost;proto=https")
                .exchange().expectStatus().isForbidden().expectBody().jsonPath("$.code").isEqualTo("HOST_NOT_ALLOWED");
    }

    @Test void rejectsUnknownOriginEvenForNonBrowserRequests() {
        client.get().uri("/actuator/health").header(HttpHeaders.ORIGIN, "https://evil.example.com")
                .exchange().expectStatus().isForbidden().expectBody().jsonPath("$.code").isEqualTo("ORIGIN_NOT_ALLOWED");
    }

    @Test void rejectsNullOriginAndSuffixAttack() {
        for (String origin : new String[]{"null", "https://client.example.com.evil.com"}) {
            client.get().uri("/actuator/health").header(HttpHeaders.ORIGIN, origin)
                    .exchange().expectStatus().isForbidden().expectBody().jsonPath("$.code").isEqualTo("ORIGIN_NOT_ALLOWED");
        }
    }

    @Test void approvedPreflightWorksWithoutJwt() {
        client.options().uri("/api/v1/auth/register").header(HttpHeaders.ORIGIN, "https://client.example.com")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "content-type,x-request-id")
                .exchange().expectStatus().isNoContent()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "https://client.example.com");
    }

    @Test void rejectsUnapprovedPreflightMethodAndHeaderWithEnvelope() {
        client.options().uri("/api/v1/auth/register").header(HttpHeaders.ORIGIN, "https://client.example.com")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "TRACE")
                .exchange().expectStatus().isForbidden().expectBody().jsonPath("$.code").isEqualTo("CORS_REJECTED");
        client.options().uri("/api/v1/auth/register").header(HttpHeaders.ORIGIN, "https://client.example.com")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS, "x-unapproved-header")
                .exchange().expectStatus().isForbidden().expectBody().jsonPath("$.code").isEqualTo("CORS_REJECTED");
    }

    @Test void missingAndInvalidJwtUseSameEnvelopeAndCorsHeaders() {
        client.get().uri("/api/v1/users/me").header(HttpHeaders.ORIGIN, "https://client.example.com")
                .exchange().expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "https://client.example.com")
                .expectHeader().value(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS,
                        value -> org.assertj.core.api.Assertions.assertThat(value).contains("X-Request-Id", "Retry-After"))
                .expectBody().jsonPath("$.code").isEqualTo("UNAUTHENTICATED");
        client.get().uri("/api/v1/users/me").headers(headers -> headers.setBearerAuth("bad-token"))
                .exchange().expectStatus().isUnauthorized().expectBody().jsonPath("$.code").isEqualTo("UNAUTHENTICATED");
    }

    @org.junit.jupiter.api.Order(1)
    @Test void upstreamConnectionFailureHasSafeEnvelope() {
        client.post().uri("/api/v1/auth/login").header("X-Request-Id", "12345678-1234-1234-1234-123456789abc")
                .exchange().expectStatus().isEqualTo(502)
                .expectHeader().valueEquals("X-Request-Id", "12345678-1234-1234-1234-123456789abc")
                .expectBody().jsonPath("$.code").isEqualTo("UPSTREAM_UNAVAILABLE")
                .jsonPath("$.traceId").isEqualTo("12345678-1234-1234-1234-123456789abc")
                .jsonPath("$.message").isEqualTo("Upstream service is unavailable");
    }

    @Test void unversionedAndFutureAuthPathsAreNotPublic() {
        for (String path : new String[]{"/auth/login", "/api/v2/auth/login", "/api/v1/auth/logout-all", "/api/v1/auth/change-password", "/api/v1/auth/change-email"}) {
            client.post().uri(path).exchange().expectStatus().isUnauthorized()
                    .expectBody().jsonPath("$.code").isEqualTo("UNAUTHENTICATED");
        }
    }

    @Test void publicAccountRecoveryAndVerificationPathsReachAuthWithoutJwt() {
        for (String path : new String[]{"/forgot-password", "/reset-password", "/confirm-email-change", "/resend-verification"}) {
            client.post().uri("/api/v1/auth" + path).exchange().expectStatus().value(status -> org.assertj.core.api.Assertions.assertThat(status).isIn(502,503))
                    .expectBody().jsonPath("$.code").value(value -> org.assertj.core.api.Assertions.assertThat(value).isIn("UPSTREAM_UNAVAILABLE","SERVICE_UNAVAILABLE"));
        }
    }

    @Test void accountActionPagesAndScriptReachAuthWithoutJwt() {
        for (String path : new String[]{"/forgot-password", "/reset-password", "/confirm-email-change", "/account-actions.js"}) {
            client.get().uri("/api/v1/auth" + path).exchange().expectStatus().value(status -> org.assertj.core.api.Assertions.assertThat(status).isIn(502,503))
                    .expectBody().jsonPath("$.code").value(value -> org.assertj.core.api.Assertions.assertThat(value).isIn("UPSTREAM_UNAVAILABLE","SERVICE_UNAVAILABLE"));
        }
    }

    @Test void allowedHostWithoutOriginCanRunHealthChecks() {
        client.get().uri("/actuator/health").exchange().expectStatus().isOk().expectBody().jsonPath("$.status").isEqualTo("UP");
    }
}
