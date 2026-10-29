package dev.kaidev.auth.controller;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.dto.request.*;
import dev.kaidev.auth.service.AccountLifecycleService;
import dev.kaidev.auth.service.PasswordRecoveryDispatcher;
import dev.kaidev.common.api.ApiPaths;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.servlet.support.ServletApi;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(ApiPaths.AUTH_V1)
public class AccountLifecycleController {
    private final AccountLifecycleService accounts;
    private final PasswordRecoveryDispatcher recovery;
    public AccountLifecycleController(AccountLifecycleService accounts, PasswordRecoveryDispatcher recovery) {
        this.accounts = accounts; this.recovery = recovery;
    }

    @PostMapping("/forgot-password")
    public ApiResponse<Void> forgot(@Valid @RequestBody EmailRequest request) {
        recovery.enqueue(request.email());
        return ServletApi.success(AuthCode.PASSWORD_RESET_REQUESTED, null);
    }
    @PostMapping("/reset-password")
    public ApiResponse<Void> reset(@Valid @RequestBody ResetPasswordRequest request) {
        accounts.resetPassword(request.token(), request.newPassword());
        return ServletApi.success(AuthCode.PASSWORD_RESET, null);
    }
    @PostMapping("/change-password")
    public ApiResponse<Void> changePassword(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody ChangePasswordRequest request) {
        accounts.changePassword(subject(jwt), request.currentPassword(), request.newPassword());
        return ServletApi.success(AuthCode.PASSWORD_CHANGED, null);
    }
    @PostMapping("/change-email")
    public ApiResponse<Void> changeEmail(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody ChangeEmailRequest request) {
        accounts.changeEmail(subject(jwt), request.currentPassword(), request.newEmail());
        return ServletApi.success(AuthCode.EMAIL_CHANGE_REQUESTED, null);
    }
    @PostMapping("/confirm-email-change")
    public ApiResponse<Void> confirm(@Valid @RequestBody ConfirmEmailChangeRequest request) {
        accounts.confirmEmailChange(request.token());
        return ServletApi.success(AuthCode.EMAIL_CHANGED, null);
    }
    private static UUID subject(Jwt jwt) {
        try { return UUID.fromString(jwt.getSubject()); }
        catch (IllegalArgumentException e) { throw new ApiException(CommonCode.UNAUTHENTICATED); }
    }
}
