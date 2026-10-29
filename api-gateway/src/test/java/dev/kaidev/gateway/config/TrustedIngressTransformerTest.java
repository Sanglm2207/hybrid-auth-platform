package dev.kaidev.gateway.config;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import static org.assertj.core.api.Assertions.*;
class TrustedIngressTransformerTest {
    @Test void untrustedPeerCannotSpoofClientOrInternalHeader() {
        var request=MockServerHttpRequest.get("/api/v1/auth/login").remoteAddress(new InetSocketAddress("203.0.113.10",80))
                .header("X-Forwarded-For","1.2.3.4").header(TrustedIngressTransformer.RESOLVED,"1.2.3.4").build();
        var result=new TrustedIngressTransformer("127.0.0.1").apply(request);
        assertThat(result.getHeaders().getFirst(TrustedIngressTransformer.RESOLVED)).isEqualTo("203.0.113.10");
        assertThat(result.getHeaders().getFirst("X-Forwarded-For")).isNull();
    }
    @Test void chainWalkStopsAtFirstUntrustedHopAndIgnoresForgedLeftPrefix() {
        var request=MockServerHttpRequest.get("/").remoteAddress(new InetSocketAddress("127.0.0.1",80))
                .header("X-Forwarded-For","1.2.3.4, 203.0.113.20, 10.0.0.1").build();
        var result=new TrustedIngressTransformer("127.0.0.1,10.0.0.1").apply(request);
        assertThat(result.getHeaders().getFirst(TrustedIngressTransformer.RESOLVED)).isEqualTo("203.0.113.20");
    }
    @Test void malformedAddressFallsBackToPeerAndHostnamesAreRejected() {
        var request=MockServerHttpRequest.get("/").remoteAddress(new InetSocketAddress("127.0.0.1",80)).header("X-Forwarded-For","attacker.example").build();
        assertThat(new TrustedIngressTransformer("127.0.0.1").apply(request).getHeaders().getFirst(TrustedIngressTransformer.RESOLVED)).isEqualTo("127.0.0.1");
        assertThatThrownBy(()->new TrustedIngressTransformer("localhost")).isInstanceOf(IllegalArgumentException.class);
    }
}
