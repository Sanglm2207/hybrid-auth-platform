package dev.kaidev.auth.controller;

import dev.kaidev.common.api.ApiPaths;
import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.dto.request.EmailRequest;
import dev.kaidev.auth.dto.request.LoginRequest;
import dev.kaidev.auth.dto.request.RefreshRequest;
import dev.kaidev.auth.dto.request.RegisterRequest;
import dev.kaidev.auth.dto.request.VerifyEmailRequest;
import dev.kaidev.auth.dto.response.RegistrationResponse;
import dev.kaidev.auth.dto.response.TokenResponse;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.service.EmailVerificationService;
import dev.kaidev.auth.service.SessionService;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.servlet.support.ServletApi;

import dev.kaidev.auth.security.JwtKeyRing;
import dev.kaidev.auth.service.LoginService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import java.util.UUID;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {
    private final UserRepository users;
    private final LoginService login;
    private final SessionService sessions;
    private final JwtKeyRing key;
    private final EmailVerificationService verification;

    AuthController(UserRepository users, LoginService login, SessionService sessions, JwtKeyRing key,
            EmailVerificationService verification) {
        this.users = users;
        this.login = login;
        this.sessions = sessions;
        this.key = key;
        this.verification = verification;
    }

    @PostMapping(ApiPaths.AUTH_V1 + "/register")
    @ResponseStatus(HttpStatus.CREATED)
    ApiResponse<RegistrationResponse> register(@Valid @RequestBody RegisterRequest request) {
        AppUser user = verification.register(request.email(), request.password());
        return ServletApi.success(AuthCode.REGISTERED, new RegistrationResponse(user.id, user.email, user.emailVerified));
    }

    @PostMapping(ApiPaths.AUTH_V1 + "/verify-email")
    ApiResponse<Void> verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        verification.verify(request.email(), request.otp());
        return ServletApi.success(AuthCode.EMAIL_VERIFIED, null);
    }

    @PostMapping({ApiPaths.AUTH_V1 + "/resend-otp", ApiPaths.AUTH_V1 + "/resend-verification"})
    ApiResponse<Void> resendOtp(@Valid @RequestBody EmailRequest request) {
        verification.resend(request.email());
        return ServletApi.success(AuthCode.OTP_REQUESTED, null);
    }

    @PostMapping(ApiPaths.AUTH_V1 + "/login")
    ApiResponse<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ServletApi.success(AuthCode.LOGGED_IN, login.login(request.email(), request.password()));
    }

    @PostMapping(ApiPaths.AUTH_V1 + "/refresh")
    ApiResponse<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ServletApi.success(AuthCode.TOKEN_REFRESHED, sessions.rotate(request.refreshToken(), users));
    }

    @PostMapping(ApiPaths.AUTH_V1 + "/logout")
    ApiResponse<Void> logout(@Valid @RequestBody RefreshRequest request) {
        sessions.revoke(request.refreshToken());
        return ServletApi.success(AuthCode.LOGGED_OUT, null);
    }

    @PostMapping(ApiPaths.AUTH_V1 + "/logout-all")
    ApiResponse<Void> logoutAll(@AuthenticationPrincipal Jwt jwt) {
        UUID userId;
        try { userId = UUID.fromString(jwt.getSubject()); }
        catch (IllegalArgumentException e) { throw new ApiException(dev.kaidev.common.api.code.CommonCode.UNAUTHENTICATED); }
        sessions.revokeAll(userId);
        return ServletApi.success(AuthCode.ALL_DEVICES_LOGGED_OUT, null);
    }

    // OAuth2 consumers require the standard JWKS shape, not an API envelope.
    @GetMapping("/.well-known/jwks.json")
    Object jwks() { return key.publicKeys().toJSONObject(); }
}
