package dev.kaidev.auth.service;

import dev.kaidev.auth.client.MailServiceClient;
import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.entity.*;
import dev.kaidev.auth.repository.*;
import dev.kaidev.auth.security.AbuseProtection;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.ClientIdentity;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.annotation.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@DataJpaTest
@Import({AccountLifecycleService.class, AccountMailNotifications.class, LoginService.class, AccountLifecycleServiceTest.Config.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AccountLifecycleServiceTest {
    private static final String CURRENT = "CurrentPassword123!", NEXT = "NextPassword456!";
    @TestConfiguration static class Config {
        @Bean PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(4); }
    }
    @Autowired AccountLifecycleService service;
    @Autowired LoginService login;
    @Autowired UserRepository users;
    @Autowired AccountActionTokenRepository tokens;
    @Autowired PasswordEncoder passwords;
    @MockitoBean dev.kaidev.auth.hardening.AuthAuditStore auditStore;
    @MockitoBean MailServiceClient mail;
    @MockitoBean SessionService sessions;
    @MockitoBean AbuseProtection protection;
    private AppUser user;

    @BeforeEach void setup() {
        user = new AppUser("owner@example.com", passwords.encode(CURRENT)); user.emailVerified = true;
        user = users.saveAndFlush(user);
    }
    @AfterEach void cleanup() { tokens.deleteAll(); users.deleteAll(); }
    private AppUser fresh() { return users.findById(user.id).orElseThrow(); }
    private String sentToken(String template, String variable) {
        return mockingDetails(mail).getInvocations().stream().filter(i -> i.getMethod().getName().equals("send")
                && template.equals(i.getArgument(1))).reduce((a, b) -> b)
                .map(i -> { Map<String, String> values = i.getArgument(2); return values.get(variable); }).orElseThrow();
    }
    private String resetToken() { service.forgotPassword(user.email); return sentToken("password-reset", "resetToken"); }
    private String changeEmailToken(String email) {
        service.changeEmail(user.id, CURRENT, email);
        return sentToken("email-change-verification", "verificationToken");
    }
    private void expireCooldowns() {
        var current = fresh(); current.passwordResetResendAt = Instant.now().minusSeconds(1);
        current.emailChangeResendAt = Instant.now().minusSeconds(1); users.saveAndFlush(current);
    }
    private static void code(String code, org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.apiCode().name()).isEqualTo(code));
    }

    @Test void forgotUnknownDoesNotCreateTokensOrSendMail() {
        service.forgotPassword("missing@example.com");
        assertThat(tokens.count()).isZero(); verifyNoInteractions(mail, sessions);
    }
    @Test void resetUsesOnlyHashedOpaqueExpiringTokenAndRevokesSessions() {
        String raw = resetToken();
        assertThat(raw).matches("[A-Za-z0-9_-]{43}");
        var stored = tokens.findByTokenHash(ClientIdentity.hash(raw)).orElseThrow();
        assertThat(stored.tokenHash).isNotEqualTo(raw).isEqualTo(ClientIdentity.hash(raw));
        assertThat(stored.expiresAt).isBetween(Instant.now().plusSeconds(895), Instant.now().plusSeconds(901));
        service.resetPassword(raw, NEXT);
        assertThat(passwords.matches(NEXT, fresh().passwordHash)).isTrue();
        assertThat(fresh().credentialRevision).isEqualTo(1);
        assertThat(tokens.findById(stored.id).orElseThrow().consumedAt).isNotNull();
        verify(sessions).revokeAll(user.id); verify(protection).reset(user.email);
        verify(mail).send(user.email, "password-changed", Map.of());
        code("INVALID_ACCOUNT_TOKEN", () -> service.resetPassword(raw, "OtherPassword789!"));
    }
    @Test void parallelResetHasExactlyOneWinner() throws Exception {
        String raw = resetToken(); var start = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(8)) {
            List<Future<Boolean>> attempts = new ArrayList<>();
            for (int i = 0; i < 8; i++) attempts.add(pool.submit(() -> {
                start.await();
                try { service.resetPassword(raw, NEXT); return true; }
                catch (ApiException e) { assertThat(e.apiCode()).isEqualTo(AuthCode.INVALID_ACCOUNT_TOKEN); return false; }
            }));
            start.countDown(); int won = 0;
            for (var attempt : attempts) if (attempt.get(10, TimeUnit.SECONDS)) won++;
            assertThat(won).isEqualTo(1);
        }
        verify(sessions).revokeAll(user.id);
    }
    @Test void expiredTokenCannotResetPassword() {
        String raw = resetToken(); var stored = tokens.findByTokenHash(ClientIdentity.hash(raw)).orElseThrow();
        stored.expiresAt = Instant.now().minusSeconds(1); tokens.saveAndFlush(stored);
        code("INVALID_ACCOUNT_TOKEN", () -> service.resetPassword(raw, NEXT));
        assertThat(passwords.matches(CURRENT, fresh().passwordHash)).isTrue(); verifyNoInteractions(sessions);
    }
    @Test void tokenPurposesCannotBeInterchanged() {
        String reset = resetToken(), email = changeEmailToken("new@example.com");
        code("INVALID_ACCOUNT_TOKEN", () -> service.confirmEmailChange(reset));
        code("INVALID_ACCOUNT_TOKEN", () -> service.resetPassword(email, NEXT));
        assertThat(fresh().email).isEqualTo(user.email); verifyNoInteractions(sessions);
    }
    @Test void cooldownSkipsRepeatedForgotRequestsWithoutInvalidatingTheToken() {
        String first = resetToken(); service.forgotPassword(user.email);
        verify(mail, times(1)).send(eq(user.email), eq("password-reset"), anyMap());
        assertThat(tokens.count()).isEqualTo(1); service.resetPassword(first, NEXT);
    }
    @Test void freshResetRequestInvalidatesAnOlderToken() {
        String first = resetToken(); expireCooldowns(); String second = resetToken();
        assertThat(second).isNotEqualTo(first);
        code("INVALID_ACCOUNT_TOKEN", () -> service.resetPassword(first, NEXT)); service.resetPassword(second, NEXT);
    }
    @Test void failedProofMailRollsBackTokenAndCooldown() {
        doThrow(new ApiException(AuthCode.EMAIL_DELIVERY_FAILED)).when(mail).send(anyString(), eq("password-reset"), anyMap());
        code("EMAIL_DELIVERY_FAILED", () -> service.forgotPassword(user.email));
        assertThat(tokens.count()).isZero(); assertThat(fresh().passwordResetResendAt).isNull();
    }
    @Test void failedReplacementMailPreservesPreviousValidResetToken() {
        String first = resetToken(); expireCooldowns();
        doThrow(new ApiException(AuthCode.EMAIL_DELIVERY_FAILED)).when(mail).send(anyString(), eq("password-reset"), anyMap());
        code("EMAIL_DELIVERY_FAILED", () -> service.forgotPassword(user.email));
        assertThat(tokens.count()).isEqualTo(1);
        service.resetPassword(first, NEXT);
    }
    @Test void enqueueFailureRollsBackPasswordReset() {
        String raw = resetToken();
        doThrow(new ApiException(AuthCode.EMAIL_DELIVERY_FAILED)).when(mail).send(anyString(), eq("password-changed"), anyMap());
        code("EMAIL_DELIVERY_FAILED", () -> service.resetPassword(raw, NEXT));
        assertThat(passwords.matches(CURRENT, fresh().passwordHash)).isTrue();
        assertThat(tokens.findByTokenHash(ClientIdentity.hash(raw)).orElseThrow().consumedAt).isNull();
    }
    @Test void unavailableRevocationRollsBackPasswordAndTokenConsumption() {
        String raw = resetToken();
        doThrow(new ApiException(AuthCode.SECURITY_UNAVAILABLE)).when(sessions).revokeAll(user.id);
        code("SECURITY_UNAVAILABLE", () -> service.resetPassword(raw, NEXT));
        assertThat(passwords.matches(CURRENT, fresh().passwordHash)).isTrue();
        assertThat(fresh().credentialRevision).isZero();
        assertThat(tokens.findByTokenHash(ClientIdentity.hash(raw)).orElseThrow().consumedAt).isNull();
        verify(mail, never()).send(anyString(), eq("password-changed"), anyMap());
        doNothing().when(sessions).revokeAll(user.id); service.resetPassword(raw, NEXT);
    }
    @Test void resetDoesNotVerifyAnUnverifiedEmail() {
        var current = fresh(); current.emailVerified = false; users.saveAndFlush(current);
        service.resetPassword(resetToken(), NEXT); assertThat(fresh().emailVerified).isFalse();
    }
    @Test void changingPasswordRequiresCurrentPasswordAndInvalidatesEveryPendingAction() {
        String reset = resetToken(), email = changeEmailToken("new@example.com");
        code("INVALID_CREDENTIALS", () -> service.changePassword(user.id, "WrongPassword123!", NEXT));
        verify(protection).failed(user.email); verifyNoInteractions(sessions);
        service.changePassword(user.id, CURRENT, NEXT);
        code("INVALID_ACCOUNT_TOKEN", () -> service.resetPassword(reset, "OtherPassword789!"));
        code("INVALID_ACCOUNT_TOKEN", () -> service.confirmEmailChange(email));
        assertThat(passwords.matches(NEXT, fresh().passwordHash)).isTrue(); verify(sessions).revokeAll(user.id);
    }
    @Test void unchangedPasswordAndEmailAreRejectedWithoutRevocation() {
        code("PASSWORD_UNCHANGED", () -> service.changePassword(user.id, CURRENT, CURRENT));
        code("EMAIL_UNCHANGED", () -> service.changeEmail(user.id, CURRENT, " OWNER@EXAMPLE.COM "));
        verifyNoInteractions(sessions, mail);
    }
    @Test void emailChangesOnlyAfterNewInboxProofAndNotifiesBothAddresses() {
        String raw = changeEmailToken(" NEW@EXAMPLE.COM ");
        assertThat(fresh().email).isEqualTo(user.email);
        verify(mail).send(eq("new@example.com"), eq("email-change-verification"), anyMap());
        verify(mail).send(user.email, "email-change-requested", Map.of("newEmail", "new@example.com"));
        service.confirmEmailChange(raw);
        assertThat(fresh().email).isEqualTo("new@example.com"); assertThat(fresh().emailVerified).isTrue();
        verify(mail).send(user.email, "email-changed", Map.of("newEmail", "new@example.com"));
        verify(mail).send("new@example.com", "email-change-confirmed", Map.of()); verify(sessions).revokeAll(user.id);
        code("INVALID_ACCOUNT_TOKEN", () -> service.confirmEmailChange(raw));
    }
    @Test void emailConfirmationInvalidatesResetProofSentToOldAddress() {
        String reset = resetToken(), email = changeEmailToken("new@example.com");
        service.confirmEmailChange(email);
        code("INVALID_ACCOUNT_TOKEN", () -> service.resetPassword(reset, NEXT));
        assertThat(passwords.matches(CURRENT, fresh().passwordHash)).isTrue();
    }
    @Test void emailChangeCooldownAndReplacementAreEnforced() {
        String first = changeEmailToken("first@example.com");
        code("ACCOUNT_ACTION_COOLDOWN", () -> service.changeEmail(user.id, CURRENT, "second@example.com"));
        expireCooldowns(); String next = changeEmailToken("second@example.com");
        code("INVALID_ACCOUNT_TOKEN", () -> service.confirmEmailChange(first));
        service.confirmEmailChange(next); assertThat(fresh().email).isEqualTo("second@example.com");
    }
    @Test void emailTakenBeforeConfirmationDoesNotChangeTheAccount() {
        String raw = changeEmailToken("new@example.com");
        users.saveAndFlush(new AppUser("new@example.com", "other-hash"));
        code("EMAIL_EXISTS", () -> service.confirmEmailChange(raw));
        assertThat(fresh().email).isEqualTo(user.email); verifyNoInteractions(sessions);
    }
    @Test void failedNewInboxMailRollsBackPendingEmailChange() {
        doThrow(new ApiException(AuthCode.EMAIL_DELIVERY_FAILED)).when(mail).send(anyString(), eq("email-change-verification"), anyMap());
        code("EMAIL_DELIVERY_FAILED", () -> service.changeEmail(user.id, CURRENT, "new@example.com"));
        assertThat(tokens.count()).isZero(); assertThat(fresh().emailChangeResendAt).isNull();
        verify(mail, never()).send(anyString(), eq("email-change-requested"), anyMap());
    }
    @Test void cleanupRemovesExpiredTokensWithoutRemovingLiveOnes() {
        String reset = resetToken(); changeEmailToken("new@example.com");
        var stored = tokens.findByTokenHash(ClientIdentity.hash(reset)).orElseThrow();
        stored.expiresAt = Instant.now().minusSeconds(1); tokens.saveAndFlush(stored);
        service.cleanupExpiredTokens(); assertThat(tokens.count()).isEqualTo(1);
    }
    @Test void loginFinishesBeforeConcurrentPasswordResetRevokesItsSession() throws Exception {
        String raw = resetToken(); var issuing = new CountDownLatch(1); var release = new CountDownLatch(1);
        when(sessions.issue(any())).thenAnswer(invocation -> { issuing.countDown(); assertThat(release.await(5, TimeUnit.SECONDS)).isTrue(); return null; });
        try (var pool = Executors.newFixedThreadPool(2)) {
            var loginFuture = pool.submit(() -> login.login(user.email, CURRENT));
            assertThat(issuing.await(5, TimeUnit.SECONDS)).isTrue();
            var resetFuture = pool.submit(() -> service.resetPassword(raw, NEXT));
            Thread.sleep(100); assertThat(resetFuture.isDone()).isFalse();
            release.countDown(); loginFuture.get(5, TimeUnit.SECONDS); resetFuture.get(5, TimeUnit.SECONDS);
        } finally { release.countDown(); }
        var ordered = inOrder(sessions); ordered.verify(sessions).issue(any()); ordered.verify(sessions).revokeAll(user.id);
        code("INVALID_CREDENTIALS", () -> login.login(user.email, CURRENT));
    }
}
