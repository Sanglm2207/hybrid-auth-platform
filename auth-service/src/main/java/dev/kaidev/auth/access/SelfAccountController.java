package dev.kaidev.auth.access;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.servlet.support.ServletApi;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

/** Auth owns account deletion/export even though their public resource paths are /users/me. */
@RestController
@RequestMapping("/api/v1/users/me")
public class SelfAccountController {
    private final AccountData accounts;
    public SelfAccountController(AccountData accounts){this.accounts=accounts;}
    @GetMapping("/export") @PreAuthorize("hasAuthority('account:export')")
    public ApiResponse<?> export(@AuthenticationPrincipal Jwt jwt){
        return ServletApi.success(CommonCode.OK,accounts.exportConfirmed(UUID.fromString(jwt.getSubject())));
    }
    @DeleteMapping @PreAuthorize("hasAuthority('account:delete')") @ResponseStatus(HttpStatus.ACCEPTED)
    public ApiResponse<?> delete(@AuthenticationPrincipal Jwt jwt,@Valid @RequestBody AccessController.Password body){
        accounts.requestDeletion(UUID.fromString(jwt.getSubject()),body.currentPassword());
        return ServletApi.success(CommonCode.OK,Map.of("state","PENDING"));
    }
}
