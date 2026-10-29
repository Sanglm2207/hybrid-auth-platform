package dev.kaidev.auth.security;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.ClientIdentity;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthRateLimitFilterTest {
    private final AbuseProtection protection = mock(AbuseProtection.class);
    private static final String KEY = "test-proxy-key-at-least-thirty-two-characters";
    private final AuthRateLimitFilter filter = new AuthRateLimitFilter(protection,
            JsonMapper.builder().addModule(new JavaTimeModule()).build(), KEY);

    private MockHttpServletRequest request() {
        var request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setRemoteAddr("127.0.0.1"); return request;
    }
    private void signed(MockHttpServletRequest request, String time) {
        request.addHeader(ClientIdentity.IP, "203.0.113.9"); request.addHeader(ClientIdentity.TIME, time);
        request.addHeader(ClientIdentity.SIGNATURE, ClientIdentity.sign(KEY, "203.0.113.9", time, "POST", "/api/v1/auth/login"));
    }

    @Test void verifiedGatewayIdentityIsUsedButRawForwardedHeadersAreIgnored() throws Exception {
        var request = request(); signed(request, Long.toString(Instant.now().getEpochSecond()));
        filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> {});
        verify(protection).rateLimit("203.0.113.9", true);
        var direct = request(); direct.addHeader("X-Forwarded-For", "1.2.3.4"); direct.addHeader(ClientIdentity.IP, "1.2.3.4");
        filter.doFilter(direct, new MockHttpServletResponse(), (req, res) -> {});
        verify(protection).rateLimit("127.0.0.1", true);
    }

    @Test void expiredSignaturesAndDuplicateHeadersCannotChangeTheRateBucket() throws Exception {
        var stale = request(); signed(stale, Long.toString(Instant.now().getEpochSecond() - 60));
        filter.doFilter(stale, new MockHttpServletResponse(), (req, res) -> {});
        var duplicate = request(); signed(duplicate, Long.toString(Instant.now().getEpochSecond())); duplicate.addHeader(ClientIdentity.IP, "1.2.3.4");
        filter.doFilter(duplicate, new MockHttpServletResponse(), (req, res) -> {});
        verify(protection, times(2)).rateLimit("127.0.0.1", true);
    }

    @Test void throttledRequestReturnsRetryAfterAndNeverReachesTheController() throws Exception {
        when(protection.rateLimit("127.0.0.1", true)).thenReturn(1501L);
        var response = new MockHttpServletResponse(); var passed = new AtomicBoolean();
        filter.doFilter(request(), response, (req, res) -> passed.set(true));
        assertThat(passed).isFalse(); assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeader("Retry-After")).isEqualTo("2");
        assertThat(response.getContentAsString()).contains("RATE_LIMITED");
    }

    @Test void encodedLoginAliasUsesTheLoginBucket() throws Exception {
        var encoded = request(); encoded.setRequestURI("/%61pi/v1/auth/lo%67in");
        filter.doFilter(encoded, new MockHttpServletResponse(), (req, res) -> {});
        verify(protection).rateLimit("127.0.0.1", true);
    }

    @Test void redisFailureFailsClosed() throws Exception {
        when(protection.rateLimit("127.0.0.1", true)).thenThrow(new ApiException(AuthCode.SECURITY_UNAVAILABLE));
        var response = new MockHttpServletResponse(); var passed = new AtomicBoolean();
        filter.doFilter(request(), response, (req, res) -> passed.set(true));
        assertThat(passed).isFalse(); assertThat(response.getStatus()).isEqualTo(503);
    }
}
