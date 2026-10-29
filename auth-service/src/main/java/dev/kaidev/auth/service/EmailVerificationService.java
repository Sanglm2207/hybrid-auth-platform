package dev.kaidev.auth.service;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.client.MailServiceClient;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.logging.ApiLog;
import dev.kaidev.common.util.EmailAddress;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class EmailVerificationService {
    private final UserRepository users;
    private final PasswordEncoder passwords;
    private final MailServiceClient mail;
    private final SecureRandom random = new SecureRandom();

    EmailVerificationService(UserRepository users, PasswordEncoder passwords, MailServiceClient mail) {
        this.users = users;
        this.passwords = passwords;
        this.mail = mail;
    }

    @Transactional
    public AppUser register(String email, String password) {
        email = normalize(email);
        if (users.findByEmail(email).isPresent())
            throw new ApiException(AuthCode.EMAIL_EXISTS);
        AppUser user = users.saveAndFlush(new AppUser(email, passwords.encode(password)));
        send(user);
        return user;
    }

    @Transactional
    public void resend(String email) {
        AppUser user = users.findByEmailForUpdate(normalize(email)).orElse(null);
        if (user == null || user.emailVerified)
            return;
        if (user.emailOtpResendAt != null && Instant.now().isBefore(user.emailOtpResendAt))
            throw new ApiException(AuthCode.OTP_COOLDOWN);
        send(user);
    }

    // Failed attempts must commit, otherwise callers could retry indefinitely.
    @Transactional(noRollbackFor = ApiException.class)
    public void verify(String email, String otp) {
        AppUser user = users.findByEmailForUpdate(normalize(email))
                .orElseThrow(() -> invalidOtp());
        if (user.emailVerified || user.emailOtpHash == null || user.emailOtpExpiresAt == null
                || !Instant.now().isBefore(user.emailOtpExpiresAt))
            throw invalidOtp();
        if (user.emailOtpAttempts >= 5)
            throw new ApiException(AuthCode.OTP_ATTEMPTS_EXCEEDED);
        user.emailOtpAttempts++;
        if (!passwords.matches(otp, user.emailOtpHash))
            throw invalidOtp();
        user.emailVerified = true;
        user.emailOtpHash = null;
        user.emailOtpExpiresAt = null;
        user.emailOtpResendAt = null;
        user.emailOtpAttempts = 0;
    }

    private void send(AppUser user) {
        String otp = String.format(Locale.ROOT, "%06d", random.nextInt(1_000_000));
        Instant now = Instant.now();
        user.emailOtpHash = passwords.encode(otp);
        user.emailOtpExpiresAt = now.plusSeconds(300);
        user.emailOtpResendAt = now.plusSeconds(60);
        user.emailOtpAttempts = 0;
        mail.send(user.email, "email-verification", Map.of("otp", otp, "expiresInMinutes", "5"));
        ApiLog.event(org.slf4j.LoggerFactory.getLogger(EmailVerificationService.class), "email.verification.sent", "OTP_SENT");
    }

    private static String normalize(String email) {
        return EmailAddress.normalize(email);
    }

    private static ApiException invalidOtp() {
        return new ApiException(AuthCode.INVALID_OTP);
    }
}
