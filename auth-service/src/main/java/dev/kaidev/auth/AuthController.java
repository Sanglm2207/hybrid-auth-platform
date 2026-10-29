package dev.kaidev.auth;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.*;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class AuthController {
    private final UserRepository users;
    private final PasswordEncoder passwords;
    private final SessionService sessions;
    private final RSAKey key;
    private final EmailVerificationService verification;

    AuthController(UserRepository users, PasswordEncoder passwords, SessionService sessions, RSAKey key,
            EmailVerificationService verification) {
        this.users = users;
        this.passwords = passwords;
        this.sessions = sessions;
        this.key = key;
        this.verification = verification;
    }

    record Credentials(@NotBlank @Email String email, @NotBlank @Size(min = 12, message = "Password must contain at least 12 characters") String password) {
    }

    record Refresh(@NotBlank String refreshToken) {
    }

    @PostMapping("/auth/register")
    @ResponseStatus(HttpStatus.CREATED)
    Object register(@Valid @RequestBody Credentials c) {
        AppUser u = verification.register(c.email(), c.password());
        return Map.of("id", u.id, "email", u.email, "emailVerified", false,
                "message", "Verification OTP sent to your email");
    }

    record VerifyEmail(@NotBlank @Email String email, @NotBlank @Pattern(regexp = "[0-9]{6}") String otp) {
    }

    record ResendOtp(@NotBlank @Email String email) {
    }

    @PostMapping("/auth/verify-email")
    Object verifyEmail(@Valid @RequestBody VerifyEmail request) {
        verification.verify(request.email(), request.otp());
        return Map.of("message", "Email verified. You can now log in.");
    }

    @PostMapping("/auth/resend-otp")
    Object resendOtp(@Valid @RequestBody ResendOtp request) {
        verification.resend(request.email());
        return Map.of("message", "If the account needs verification, an OTP has been sent");
    }

    @PostMapping("/auth/login")
    Object login(@Valid @RequestBody Credentials c) {
        AppUser u = users.findByEmail(c.email().trim().toLowerCase(Locale.ROOT))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials"));
        if (!passwords.matches(c.password(), u.passwordHash))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        if (!u.emailVerified)
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Verify your email before logging in");
        return sessions.issue(u);
    }

    @PostMapping("/auth/refresh")
    Object refresh(@Valid @RequestBody Refresh r) {
        return sessions.rotate(r.refreshToken(), users);
    }

    @PostMapping("/auth/logout")
    ResponseEntity<Void> logout(@Valid @RequestBody Refresh r) {
        sessions.revoke(r.refreshToken());
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/.well-known/jwks.json")
    Object jwks() {
        return new JWKSet(key.toPublicJWK()).toJSONObject();
    }
}
