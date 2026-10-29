package dev.kaidev.auth.security;

import dev.kaidev.common.security.ClientIdentity;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

@Service
public class AbuseProtection {
    private static final DefaultRedisScript<Long> RATE = SecurityState.script("rate-limit");
    private static final DefaultRedisScript<Long> ATTEMPT = SecurityState.script("login-attempt");
    private final SecurityState state;
    private final int loginLimit, otherLimit, threshold;
    private final long windowMs, observationMs, lockMs;

    public AbuseProtection(SecurityState state,
            @Value("${app.security.login-ip-limit:20}") int loginLimit,
            @Value("${app.security.auth-ip-limit:60}") int otherLimit,
            @Value("${app.security.rate-window-seconds:60}") long window,
            @Value("${app.security.login-failure-threshold:5}") int threshold,
            @Value("${app.security.login-observation-seconds:900}") long observation,
            @Value("${app.security.login-lock-seconds:300}") long lock) {
        if (loginLimit < 1 || otherLimit < 1 || threshold < 1 || threshold > 100
                || window < 1 || window > 3600 || observation < 1 || observation > 86400 || lock < 1 || lock > 3600)
            throw new IllegalArgumentException("Invalid abuse protection configuration");
        this.state = state; this.loginLimit = loginLimit; this.otherLimit = otherLimit; this.threshold = threshold;
        windowMs = window * 1000; observationMs = observation * 1000; lockMs = lock * 1000;
    }

    public long rateLimit(String ip, boolean login) {
        return state.execute(RATE, List.of(state.key("rate:" + (login ? "login:" : "auth:") + ClientIdentity.hash(ip))),
                Integer.toString(login ? loginLimit : otherLimit), Long.toString(windowMs));
    }
    public long lockedFor(String email) { return attempt(email, "check"); }
    public long failed(String email) { return attempt(email, "failure"); }
    public long succeeded(String email) { return attempt(email, "success"); }
    private long attempt(String email, String operation) {
        String hash = ClientIdentity.hash(email);
        return state.execute(ATTEMPT, List.of(state.key("failures:" + hash), state.key("lock:" + hash)), operation,
                Integer.toString(threshold), Long.toString(observationMs), Long.toString(lockMs));
    }
}
