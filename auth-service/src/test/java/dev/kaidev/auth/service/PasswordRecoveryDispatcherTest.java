package dev.kaidev.auth.service;
import dev.kaidev.auth.outbox.AuthOutbox;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.*;
class PasswordRecoveryDispatcherTest {
    @Test void submissionPersistsWorkWithoutAccountLookup() {
        var outbox=mock(AuthOutbox.class);
        new PasswordRecoveryDispatcher(outbox).enqueue("owner@example.com");
        verify(outbox).recovery("owner@example.com"); verifyNoMoreInteractions(outbox);
    }
}
