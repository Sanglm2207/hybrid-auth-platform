package dev.kaidev.common.resilience;

import dev.kaidev.common.exception.ApiException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.*;
import static org.assertj.core.api.Assertions.*;

class DependencyGuardTest {
    @Test void retriesSafeReadOnceAndNeverRetriesWrite() {
        var guard = new DependencyGuard("read-test");
        var calls = new AtomicInteger();
        assertThat(guard.read(() -> {
            if (calls.incrementAndGet() == 1) throw new ResourceAccessException("connection lost");
            return "recovered";
        })).isEqualTo("recovered");
        assertThat(calls).hasValue(2);
        calls.set(0);
        assertThatThrownBy(() -> guard.once(() -> {
            calls.incrementAndGet(); throw new ResourceAccessException("ambiguous write");
        })).isInstanceOf(ResourceAccessException.class);
        assertThat(calls).hasValue(1);
    }

    @Test void businessErrorsDoNotRetryOrOpenCircuit() {
        var guard = new DependencyGuard("business-test");
        var calls = new AtomicInteger();
        for (int i = 0; i < 10; i++) assertThatThrownBy(() -> guard.read(() -> {
            calls.incrementAndGet(); throw new HttpClientErrorException(HttpStatus.FORBIDDEN);
        })).isInstanceOf(HttpClientErrorException.class);
        assertThat(calls).hasValue(10);
        assertThat(guard.breaker().getState().name()).isEqualTo("CLOSED");
    }

    @Test void opensCircuitIsolatesDependencyAndRecoversThroughHalfOpen() {
        var failed = new DependencyGuard("failed-test");
        var healthy = new DependencyGuard("healthy-test");
        var calls = new AtomicInteger();
        for (int i = 0; i < 5; i++) assertThatThrownBy(() -> failed.once(() -> {
            calls.incrementAndGet(); throw new ResourceAccessException("offline");
        })).isInstanceOf(ResourceAccessException.class);
        assertThatThrownBy(() -> failed.once(() -> calls.incrementAndGet())).isInstanceOf(ApiException.class);
        assertThat(calls).hasValue(5);
        assertThat(healthy.once(() -> "ok")).isEqualTo("ok");
        failed.breaker().transitionToHalfOpenState();
        failed.once(() -> "ok"); failed.once(() -> "ok");
        assertThat(failed.breaker().getState().name()).isEqualTo("CLOSED");
    }

    @Test void retriesAreBoundedAndPreserveInterrupt() {
        var guard = new DependencyGuard("bounded-test");
        var calls = new AtomicInteger();
        assertThatThrownBy(() -> guard.read(() -> {
            calls.incrementAndGet(); throw new ResourceAccessException("offline");
        })).isInstanceOf(ResourceAccessException.class);
        assertThat(calls).hasValue(2);
        Thread.currentThread().interrupt();
        try {
            assertThatThrownBy(() -> guard.read(() -> { throw new ResourceAccessException("offline"); }))
                    .isInstanceOf(ApiException.class);
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        } finally { Thread.interrupted(); }
    }

    @Test void durableBackoffHasJitterAndNeverExceedsFiveMinutes() {
        for (int attempt = 0; attempt < 40; attempt++) {
            long cap = Math.min(300, 1L << Math.min(9, Math.max(1, attempt)));
            assertThat(DependencyGuard.backoffSeconds(attempt)).isBetween(Math.max(1, cap / 2), cap);
        }
    }
}
