package dev.kaidev.auth;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class EmailVerificationService {
    private final UserRepository users;
    private final PasswordEncoder passwords;
    private final JavaMailSender mail;
    private final String host;
    private final String from;
    private final SecureRandom random = new SecureRandom();

    EmailVerificationService(UserRepository users, PasswordEncoder passwords, JavaMailSender mail,
            @Value("${spring.mail.host}") String host, @Value("${app.email-from}") String from) {
        this.users = users;
        this.passwords = passwords;
        this.mail = mail;
        this.host = host;
        this.from = from;
    }

    @Transactional
    public AppUser register(String email, String password) {
        email = normalize(email);
        if (users.findByEmail(email).isPresent())
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email exists");
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
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Wait 60 seconds before requesting another OTP");
        send(user);
    }

    // Failed attempts must commit, otherwise callers could retry indefinitely.
    @Transactional(noRollbackFor = ResponseStatusException.class)
    public void verify(String email, String otp) {
        AppUser user = users.findByEmailForUpdate(normalize(email))
                .orElseThrow(() -> invalidOtp());
        if (user.emailVerified || user.emailOtpHash == null || user.emailOtpExpiresAt == null
                || !Instant.now().isBefore(user.emailOtpExpiresAt))
            throw invalidOtp();
        if (user.emailOtpAttempts >= 5)
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Too many attempts. Request another OTP");
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
        if (host.isBlank() || from.isBlank())
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Email delivery is not configured");
        String otp = String.format(Locale.ROOT, "%06d", random.nextInt(1_000_000));
        Instant now = Instant.now();
        user.emailOtpHash = passwords.encode(otp);
        user.emailOtpExpiresAt = now.plusSeconds(300);
        user.emailOtpResendAt = now.plusSeconds(60);
        user.emailOtpAttempts = 0;
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(user.email);
        message.setSubject("Verify your email");
        message.setText("Your email verification code is: " + otp
                + "\nThis code expires in 5 minutes. If you did not request it, ignore this email.");
        try {
            mail.send(message);
            System.out.println("Sent verification email to " + user.email + " with OTP: " + otp);
        } catch (MailException e) {
            // Never expose SMTP credentials, provider responses, or the OTP to the client.
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Unable to send verification email");
        }
    }

    private static String normalize(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private static ResponseStatusException invalidOtp() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired OTP");
    }
}
