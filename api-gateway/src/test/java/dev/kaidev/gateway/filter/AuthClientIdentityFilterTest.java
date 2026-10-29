package dev.kaidev.gateway.filter;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dev.kaidev.common.security.ClientIdentity;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.*;

class AuthClientIdentityFilterTest {
    private static final String KEY = "test-proxy-key-at-least-thirty-two-characters";

    @Test void callerHeadersAreReplacedWithASignatureForTheActualPeer() {
        var request = MockServerHttpRequest.post("http://localhost/api/v1/auth/login")
                .remoteAddress(new InetSocketAddress("203.0.113.8", 1234))
                .header(ClientIdentity.IP, "1.2.3.4").header(ClientIdentity.TIME, "0")
                .header(ClientIdentity.SIGNATURE, "forged").build();
        var exchange = MockServerWebExchange.from(request);
        var filter = new AuthClientIdentityFilter(KEY, JsonMapper.builder().build());
        var checked = new AtomicBoolean();
        filter.filter(exchange, next -> {
            var headers = next.getRequest().getHeaders();
            assertThat(headers.getFirst(ClientIdentity.IP)).isEqualTo("203.0.113.8");
            assertThat(ClientIdentity.verify(KEY, headers.getFirst(ClientIdentity.IP), headers.getFirst(ClientIdentity.TIME),
                    headers.getFirst(ClientIdentity.SIGNATURE), "POST", "/api/v1/auth/login")).isTrue();
            checked.set(true); return Mono.empty();
        }).block();
        assertThat(checked).isTrue();
    }

    @Test void missingSharedKeyFailsClosedForAuth() {
        var exchange = MockServerWebExchange.from(MockServerHttpRequest.post("http://localhost/api/v1/auth/login")
                .remoteAddress(new InetSocketAddress("203.0.113.8", 1234)));
        var passed = new AtomicBoolean();
        new AuthClientIdentityFilter("", JsonMapper.builder().addModule(new JavaTimeModule()).build())
                .filter(exchange, next -> { passed.set(true); return Mono.empty(); }).block();
        assertThat(passed).isFalse(); assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(503);
    }
}
