package dev.kaidev.auth.service;

import dev.kaidev.common.exception.ApiException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class PasswordRecoveryDispatcherTest {
    @Test void httpSubmissionDoesNotLookUpAccountsOrWaitForDelivery() {
        var service = mock(AccountLifecycleService.class); var queued = new AtomicReference<Runnable>();
        var dispatcher = new PasswordRecoveryDispatcher(queued::set, service);
        dispatcher.enqueue("owner@example.com"); verifyNoInteractions(service);
        queued.get().run(); verify(service).forgotPassword("owner@example.com");
    }
    @Test void workerFailureIsContainedAndQueueRejectionIsGeneric() {
        var service = mock(AccountLifecycleService.class);
        doThrow(new IllegalStateException("secret-provider-error")).when(service).forgotPassword(anyString());
        new PasswordRecoveryDispatcher(Runnable::run, service).enqueue("owner@example.com");
        var rejected = new PasswordRecoveryDispatcher(task -> { throw new RejectedExecutionException("secret-internal-detail"); }, service);
        assertThatThrownBy(() -> rejected.enqueue("owner@example.com")).isInstanceOfSatisfying(ApiException.class, e -> {
            assertThat(e.getStatusCode().value()).isEqualTo(503);
            assertThat(e.getMessage()).doesNotContain("secret-internal-detail", "owner@example.com");
        });
    }
}
