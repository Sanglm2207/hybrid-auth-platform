package dev.kaidev.common.resilience;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import io.github.resilience4j.circuitbreaker.*;
import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;
import org.springframework.web.client.*;

/** One guard per dependency per JVM. Only explicitly safe reads may retry. */
public final class DependencyGuard {
    private final CircuitBreaker breaker;

    public DependencyGuard(String dependency) {
        breaker = CircuitBreaker.of(dependency, CircuitBreakerConfig.custom()
                .slidingWindowSize(10).minimumNumberOfCalls(5).failureRateThreshold(50)
                .waitDurationInOpenState(Duration.ofSeconds(10))
                .permittedNumberOfCallsInHalfOpenState(2)
                .ignoreException(error -> error instanceof RestClientResponseException response
                        && !response.getStatusCode().is5xxServerError())
                .build());
        io.micrometer.core.instrument.Gauge.builder("dependency.circuit.state", breaker, value -> switch (value.getState()) {
            case CLOSED, DISABLED, METRICS_ONLY -> 0;
            case HALF_OPEN -> 2;
            default -> 1;
        }).tag("dependency", dependency).register(io.micrometer.core.instrument.Metrics.globalRegistry);
    }

    public CircuitBreaker breaker() { return breaker; }

    /** No retry: writes are retried by durable workers with stable operation IDs. */
    public <T> T once(Supplier<T> operation) {
        try { return breaker.executeSupplier(operation); }
        catch (CallNotPermittedException e) { throw new ApiException(CommonCode.SERVICE_UNAVAILABLE); }
    }

    /** At most two attempts; timeout remains bounded on the underlying HTTP client. */
    public <T> T read(Supplier<T> operation) {
        for (int attempt = 0; ; attempt++) {
            try { return once(operation); }
            catch (RestClientException e) {
                if (attempt != 0 || !transientFailure(e)) throw e;
                try { Thread.sleep(ThreadLocalRandom.current().nextLong(50, 101)); }
                catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new ApiException(CommonCode.SERVICE_UNAVAILABLE);
                }
            }
        }
    }

    private static boolean transientFailure(RestClientException error) {
        return error instanceof ResourceAccessException || error instanceof RestClientResponseException response
                && (response.getStatusCode().value() == 502 || response.getStatusCode().value() == 503
                || response.getStatusCode().value() == 504);
    }

    /** Equal jitter, capped at five minutes. Persist the resulting next-attempt time. */
    public static long backoffSeconds(int attempts) {
        long cap = Math.min(300, 1L << Math.min(9, Math.max(1, attempts)));
        return ThreadLocalRandom.current().nextLong(Math.max(1, cap / 2), cap + 1);
    }
}
