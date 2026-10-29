package dev.kaidev.auth.constant;

import dev.kaidev.common.api.code.ApiCode;

import org.springframework.http.HttpStatus;

public enum AuthCode implements ApiCode {
    REGISTERED(HttpStatus.CREATED, "Registration successful. Check your email for the verification OTP"),
    EMAIL_VERIFIED(HttpStatus.OK, "Email verified. You can now log in"),
    OTP_REQUESTED(HttpStatus.OK, "If the account needs verification, an OTP will be sent"),
    LOGGED_IN(HttpStatus.OK, "Login successful"),
    TOKEN_REFRESHED(HttpStatus.OK, "Token refreshed successfully"),
    LOGGED_OUT(HttpStatus.OK, "Logout successful"),
    ALL_DEVICES_LOGGED_OUT(HttpStatus.OK, "All refresh sessions have been revoked"),
    RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS, "Too many authentication requests. Try again later"),
    ACCOUNT_TEMPORARILY_LOCKED(HttpStatus.TOO_MANY_REQUESTS, "Too many incorrect login attempts. Try again later"),
    SECURITY_UNAVAILABLE(HttpStatus.SERVICE_UNAVAILABLE, "Authentication security state is temporarily unavailable"),
    PASSWORD_RESET_REQUESTED(HttpStatus.OK, "If the account exists, password reset instructions will be sent"),
    PASSWORD_RESET(HttpStatus.OK, "Password reset successful. Log in with your new password"),
    PASSWORD_CHANGED(HttpStatus.OK, "Password changed. Log in again on your devices"),
    EMAIL_CHANGE_REQUESTED(HttpStatus.OK, "Check the new email address to confirm the change"),
    EMAIL_CHANGED(HttpStatus.OK, "Email changed. Log in with your new email address"),
    INVALID_ACCOUNT_TOKEN(HttpStatus.BAD_REQUEST, "Account token is invalid, expired, or already used"),
    PASSWORD_UNCHANGED(HttpStatus.BAD_REQUEST, "Choose a different password"),
    EMAIL_UNCHANGED(HttpStatus.BAD_REQUEST, "Choose a different email address"),
    ACCOUNT_ACTION_COOLDOWN(HttpStatus.TOO_MANY_REQUESTS, "Wait 60 seconds before requesting another email change"),
    LAST_ADMINISTRATOR(HttpStatus.CONFLICT, "At least one active administrator must remain"),
    SESSION_REVOKED(HttpStatus.OK, "Session revoked"),
    DEVICE_REVOKED(HttpStatus.OK, "Device sessions revoked and device removed"),
    SESSION_NOT_FOUND(HttpStatus.NOT_FOUND, "Session does not exist"),
    DEVICE_NOT_FOUND(HttpStatus.NOT_FOUND, "Device does not exist"),
    SESSION_LIMIT_REACHED(HttpStatus.TOO_MANY_REQUESTS, "Too many active sessions. Revoke an existing session first"),
    ACCOUNT_DISABLED(HttpStatus.FORBIDDEN, "Account is deactivated"),
    ACCOUNT_DEACTIVATED(HttpStatus.OK, "Account deactivated"),
    ROLES_UPDATED(HttpStatus.OK, "Roles updated. Affected sessions have been revoked"),
    ROLE_UPDATED(HttpStatus.OK, "Role permissions updated"),
    INVALID_ROLE_POLICY(HttpStatus.BAD_REQUEST, "Invalid role or permission policy"),
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
