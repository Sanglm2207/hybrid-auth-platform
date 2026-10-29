package dev.kaidev.gateway.filter;

import dev.kaidev.gateway.config.properties.GatewayAccessProperties;

import static org.assertj.core.api.Assertions.*;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

class GatewayPolicyTest {
    private GatewayAccessFilter filter(boolean strict) {
        return new GatewayAccessFilter(new GatewayAccessProperties(List.of("localhost", "[::1]"),
                List.of("https://client.example.com"), strict), JsonMapper.builder().addModule(new JavaTimeModule()).build());
    }

    @Test void strictOriginBlocksApiCallsWithoutOrigin() {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("http://localhost/api/v1/auth/login").header("Host", "localhost"));
        AtomicBoolean forwarded = new AtomicBoolean();
        filter(true).filter(exchange, ignored -> { forwarded.set(true); return Mono.empty(); }).block();
        assertThat(forwarded).isFalse();
        assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(403);
        assertThat(exchange.getResponse().getBodyAsString().block()).contains("ORIGIN_NOT_ALLOWED");
    }

    @Test void strictOriginKeepsHealthChecksAvailable() {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("http://localhost/actuator/health").header("Host", "localhost"));
        AtomicBoolean forwarded = new AtomicBoolean();
        filter(true).filter(exchange, ignored -> { forwarded.set(true); return Mono.empty(); }).block();
        assertThat(forwarded).isTrue();
    }

    @Test void localIpv6HostIsAllowed() {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("http://[::1]/actuator/health").header("Host", "[::1]"));
        AtomicBoolean forwarded = new AtomicBoolean();
        filter(false).filter(exchange, ignored -> { forwarded.set(true); return Mono.empty(); }).block();
        assertThat(forwarded).isTrue();
    }

    @Test void wildcardAndPathConfigurationIsRejected() {
        assertThatThrownBy(() -> new GatewayAccessProperties(List.of("*"), List.of("https://client.example.com"), false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new GatewayAccessProperties(List.of("localhost"), List.of("https://*.example.com"), false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new GatewayAccessProperties(List.of("localhost"), List.of("https://client.example.com/path"), false))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
