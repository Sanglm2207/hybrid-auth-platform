package dev.kaidev.auth.controller;

import dev.kaidev.auth.dto.request.LoginRequest;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.service.EmailVerificationService;
import dev.kaidev.auth.service.SessionService;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ResponseStatusException;

class AuthControllerTest {
    private final UserRepository users = mock(UserRepository.class);
    private final PasswordEncoder passwords = mock(PasswordEncoder.class);
    private final SessionService sessions = mock(SessionService.class);
    private final AuthController controller = new AuthController(users, passwords, sessions, null,
            mock(EmailVerificationService.class));

    @Test
    void unverifiedUserCannotLogInEvenWithCorrectPassword() {
        AppUser user = new AppUser("test@example.com", "hash");
        when(users.findByEmail(user.email)).thenReturn(Optional.of(user));
        when(passwords.matches("StrongPassword123!", "hash")).thenReturn(true);
        assertThatThrownBy(() -> controller.login(new LoginRequest(user.email, "StrongPassword123!")))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        error -> assertThat(error.getStatusCode().value()).isEqualTo(403));
        verifyNoInteractions(sessions);
    }

    @Test
    void verifiedUserCanLogIn() {
        AppUser user = new AppUser("test@example.com", "hash");
        user.emailVerified = true;
        when(users.findByEmail(user.email)).thenReturn(Optional.of(user));
        when(passwords.matches("StrongPassword123!", "hash")).thenReturn(true);
        controller.login(new LoginRequest(user.email, "StrongPassword123!"));
        verify(sessions).issue(user);
    }
}
