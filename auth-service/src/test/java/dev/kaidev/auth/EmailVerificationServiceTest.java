package dev.kaidev.auth;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@DataJpaTest(properties = {"spring.mail.host=smtp.test", "app.email-from=sender@example.com"})
@Import({EmailVerificationService.class, EmailVerificationServiceTest.Config.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class EmailVerificationServiceTest {
    @TestConfiguration
    static class Config {
        @Bean PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(4); }
    }

    @Autowired EmailVerificationService service;
    @Autowired UserRepository users;
    @MockitoBean JavaMailSender mail;

    @AfterEach
    void cleanUp() { users.deleteAll(); }

    private String register() {
        service.register(" Test@Example.com ", "StrongPassword123!");
        return lastOtp();
    }

    private String lastOtp() {
        ArgumentCaptor<SimpleMailMessage> messages = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mail, atLeastOnce()).send(messages.capture());
        SimpleMailMessage message = messages.getValue();
        assertThat(message.getTo()).containsExactly("test@example.com");
        return message.getText().split(": ")[1].substring(0, 6);
    }

    @Test
    void registrationSendsOtpAndVerificationConsumesIt() {
        String otp = register();
        AppUser user = users.findByEmail("test@example.com").orElseThrow();
        assertThat(user.emailVerified).isFalse();
        assertThat(user.emailOtpHash).isNotEqualTo(otp);
        service.verify("TEST@example.com", otp);
        user = users.findById(user.id).orElseThrow();
        assertThat(user.emailVerified).isTrue();
        assertThat(user.emailOtpHash).isNull();
        assertThatThrownBy(() -> service.verify("test@example.com", otp))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void failedAttemptsCommitAndBlockEvenCorrectOtpAfterFiveFailures() {
        String otp = register();
        String wrong = otp.equals("000000") ? "111111" : "000000";
        for (int i = 0; i < 5; i++) {
            assertThatThrownBy(() -> service.verify("test@example.com", wrong))
                    .isInstanceOf(ResponseStatusException.class);
        }
        assertThat(users.findByEmail("test@example.com").orElseThrow().emailOtpAttempts).isEqualTo(5);
        assertThatThrownBy(() -> service.verify("test@example.com", otp))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        error -> assertThat(error.getStatusCode().value()).isEqualTo(429));
        assertThat(users.findByEmail("test@example.com").orElseThrow().emailVerified).isFalse();
    }

    @Test
    void expiredOtpCannotVerify() {
        String otp = register();
        AppUser user = users.findByEmail("test@example.com").orElseThrow();
        user.emailOtpExpiresAt = Instant.now().minusSeconds(1);
        users.saveAndFlush(user);
        assertThatThrownBy(() -> service.verify("test@example.com", otp))
                .isInstanceOf(ResponseStatusException.class);
        assertThat(users.findById(user.id).orElseThrow().emailVerified).isFalse();
    }

    @Test
    void resendEnforcesCooldownThenReplacesChallenge() {
        register();
        assertThatThrownBy(() -> service.resend("test@example.com"))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        error -> assertThat(error.getStatusCode().value()).isEqualTo(429));
        AppUser user = users.findByEmail("test@example.com").orElseThrow();
        user.emailOtpResendAt = Instant.now().minusSeconds(1);
        user.emailOtpAttempts = 5;
        String previousHash = user.emailOtpHash;
        users.saveAndFlush(user);
        service.resend("test@example.com");
        user = users.findById(user.id).orElseThrow();
        assertThat(user.emailOtpHash).isNotEqualTo(previousHash);
        assertThat(user.emailOtpAttempts).isZero();
        verify(mail, times(2)).send(any(SimpleMailMessage.class));
        service.verify("test@example.com", lastOtp());
    }

    @Test
    void failedMailDeliveryRollsBackRegistration() {
        doThrow(new MailSendException("provider failure")).when(mail).send(any(SimpleMailMessage.class));
        assertThatThrownBy(() -> service.register("test@example.com", "StrongPassword123!"))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        error -> assertThat(error.getStatusCode().value()).isEqualTo(503));
        assertThat(users.findByEmail("test@example.com")).isEmpty();
    }

    @Test
    void missingSmtpConfigurationDoesNotSendMail() {
        UserRepository repository = mock(UserRepository.class);
        when(repository.saveAndFlush(any(AppUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        EmailVerificationService unconfigured = new EmailVerificationService(repository,
                new BCryptPasswordEncoder(4), mail, "", "");
        assertThatThrownBy(() -> unconfigured.register("test@example.com", "StrongPassword123!"))
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        error -> assertThat(error.getStatusCode().value()).isEqualTo(503));
        verifyNoInteractions(mail);
    }

    @Test
    void failedResendPreservesPreviousChallenge() {
        String otp = register();
        AppUser user = users.findByEmail("test@example.com").orElseThrow();
        user.emailOtpResendAt = Instant.now().minusSeconds(1);
        users.saveAndFlush(user);
        doThrow(new MailSendException("provider failure")).when(mail).send(any(SimpleMailMessage.class));
        assertThatThrownBy(() -> service.resend("test@example.com"))
                .isInstanceOf(ResponseStatusException.class);
        service.verify("test@example.com", otp);
        assertThat(users.findById(user.id).orElseThrow().emailVerified).isTrue();
    }

    @Test
    void resendUnknownOrVerifiedAccountSendsNothing() {
        service.resend("missing@example.com");
        verifyNoInteractions(mail);
        service.verify("test@example.com", register());
        clearInvocations(mail);
        service.resend("test@example.com");
        verifyNoInteractions(mail);
    }
}
