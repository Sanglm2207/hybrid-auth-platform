package dev.kaidev.auth.security;

import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.service.*;
import dev.kaidev.common.exception.ApiException;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class LoginProtectionTest {
    private final UserRepository users = mock(UserRepository.class);
    private final PasswordEncoder passwords = mock(PasswordEncoder.class);
    private final SessionService sessions = mock(SessionService.class);
    private final AbuseProtection protection = mock(AbuseProtection.class);

    @Test void unknownAccountStillChecksDummyPasswordAndUpdatesFailures() {
        when(passwords.encode(anyString())).thenReturn("dummy-bcrypt-hash");
        var service = new LoginService(users, passwords, sessions, protection);
        assertThatThrownBy(() -> service.login(" UNKNOWN@EXAMPLE.COM ", "password"))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.apiCode().name()).isEqualTo("INVALID_CREDENTIALS"));
        verify(passwords).matches("password", "dummy-bcrypt-hash"); verify(protection).failed("unknown@example.com");
        verifyNoInteractions(sessions);
    }

    @Test void lockedAccountDoesNotCheckPasswordOrIssueTokens() {
        when(protection.lockedFor("test@example.com")).thenReturn(1000L);
        var service = new LoginService(users, passwords, sessions, protection);
        assertLocked(() -> service.login("test@example.com", "password"));
        verify(passwords, never()).matches(anyString(), anyString()); verifyNoInteractions(users, sessions);
    }

    @Test void concurrentLockAppearingDuringPasswordCheckBlocksCorrectPassword() {
        var user = new AppUser("test@example.com", "hash"); user.emailVerified = true;
        when(users.findByEmailForUpdate(user.email)).thenReturn(Optional.of(user));
        when(passwords.matches("password", "hash")).thenReturn(true);
        when(protection.succeeded(user.email)).thenReturn(1000L);
        var service = new LoginService(users, passwords, sessions, protection);
        assertLocked(() -> service.login(user.email, "password")); verifyNoInteractions(sessions);
    }

    @Test void unavailableRedisNeverFallsBackToUnprotectedState() {
        var redis = mock(StringRedisTemplate.class);
        when(redis.opsForValue()).thenThrow(new DataAccessResourceFailureException("secret-connection-detail"));
        var state = new SecurityState(redis, "security:{test}:");
        assertThatThrownBy(() -> state.get(state.key("test")))
                .isInstanceOfSatisfying(ApiException.class, e -> {
                    assertThat(e.apiCode().name()).isEqualTo("SECURITY_UNAVAILABLE");
                    assertThat(e.getMessage()).doesNotContain("secret-connection-detail");
                });
    }
    private static void assertLocked(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOfSatisfying(ApiException.class,
                e -> assertThat(e.apiCode().name()).isEqualTo("ACCOUNT_TEMPORARILY_LOCKED"));
    }
}
