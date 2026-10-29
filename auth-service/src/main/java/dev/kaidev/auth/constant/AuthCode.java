package dev.kaidev.auth.constant;

import dev.kaidev.common.api.code.ApiCode;

import org.springframework.http.HttpStatus;

public enum AuthCode implements ApiCode {
    REGISTERED(HttpStatus.CREATED, "Registration successful. Check your email for the verification OTP"),
    EMAIL_VERIFIED(HttpStatus.OK, "Email verified. You can now log in"),
    OTP_REQUESTED(HttpStatus.OK, "If the account needs verification, an OTP has been sent"),
    LOGGED_IN(HttpStatus.OK, "Login successful"),
    TOKEN_REFRESHED(HttpStatus.OK, "Token refreshed successfully"),
    LOGGED_OUT(HttpStatus.OK, "Logout successful"),
    ALL_DEVICES_LOGGED_OUT(HttpStatus.OK, "All refresh sessions have been revoked"),
    RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS, "Too many authentication requests. Try again later"),
    ACCOUNT_TEMPORARILY_LOCKED(HttpStatus.TOO_MANY_REQUESTS, "Too many incorrect login attempts. Try again later"),
    SECURITY_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "Authentication security state is temporarily unavailable"),
    EMAIL_EXISTS(HttpStatus.CONFLICT, "Email is already registered"),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "Email or password is incorrect"),
    EMAIL_NOT_VERIFIED(HttpStatus.FORBIDDEN, "Verify your email before logging in"),
    INVALID_OTP(HttpStatus.BAD_REQUEST, "OTP is invalid or expired"),
    OTP_ATTEMPTS_EXCEEDED(HttpStatus.TOO_MANY_REQUESTS, "Too many incorrect attempts. Request another OTP"),
    OTP_COOLDOWN(HttpStatus.TOO_MANY_REQUESTS, "Wait 60 seconds before requesting another OTP"),
    EMAIL_NOT_CONFIGURED(HttpStatus.SERVICE_UNAVAILABLE, "Email delivery is not configured"),
    EMAIL_DELIVERY_FAILED(HttpStatus.SERVICE_UNAVAILABLE, "Unable to send verification email. Try again later"),
    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "Refresh token is invalid, expired, or already used");

    private final HttpStatus status;
    private final String message;
    AuthCode(HttpStatus status, String message) { this.status = status; this.message = message; }
    public HttpStatus status() { return status; }
    public String message() { return message; }
}
