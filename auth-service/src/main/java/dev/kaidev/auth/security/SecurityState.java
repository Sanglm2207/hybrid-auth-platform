package dev.kaidev.auth.security;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.SecurityAudit;
import java.util.List;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

@Component
public class SecurityState {
    private final StringRedisTemplate redis;
    private final String prefix;

    public SecurityState(StringRedisTemplate redis, @Value("${app.security.redis-prefix:security:{auth}:}") String prefix) {
        if (!prefix.matches("[a-zA-Z0-9:_-]*\\{[a-zA-Z0-9_-]+\\}[a-zA-Z0-9:_-]*"))
            throw new IllegalArgumentException("Security Redis prefix must contain one cluster hash tag");
        this.redis = redis;
        this.prefix = prefix;
    }

    public String key(String suffix) { return prefix + suffix; }

    public String get(String key) {
        try { return redis.opsForValue().get(key); }
        catch (DataAccessException e) { throw unavailable(e); }
    }

    public java.util.Set<String> sessionIds(String key) {
        try {
            var result = redis.opsForZSet().rangeByScore(key, System.currentTimeMillis(), Double.POSITIVE_INFINITY, 0, 100);
            if (result == null) throw unavailable();
            return result;
        } catch (DataAccessException e) { throw unavailable(e); }
    }

    public long increment(String key) {
        try {
            Long value = redis.opsForValue().increment(key);
            if (value == null) throw unavailable();
            return value;
        } catch (DataAccessException e) { throw unavailable(e); }
    }

    public long execute(DefaultRedisScript<Long> script, List<String> keys, String... args) {
        try {
            Long result = redis.execute(script, keys, (Object[]) args);
            if (result == null) throw unavailable();
            return result;
        } catch (DataAccessException e) { throw unavailable(e); }
    }

    public static DefaultRedisScript<Long> script(String name) {
        var script = new DefaultRedisScript<Long>();
        script.setLocation(new ClassPathResource("redis/" + name + ".lua"));
        script.setResultType(Long.class);
        return script;
    }

    private static ApiException unavailable(Throwable error) {
        boolean connection=error instanceof org.springframework.data.redis.RedisConnectionFailureException||error instanceof org.springframework.dao.QueryTimeoutException;
        dev.kaidev.common.observability.SecurityMetrics.redisFailure(connection);
        return unavailable();
    }
    private static ApiException unavailable() {
        SecurityAudit.record(SecurityAudit.Event.SECURITY_STATE_FAILURE, SecurityAudit.Outcome.UNAVAILABLE, null, MDC.get("correlationId"));
        return new ApiException(AuthCode.SECURITY_UNAVAILABLE);
    }
}
