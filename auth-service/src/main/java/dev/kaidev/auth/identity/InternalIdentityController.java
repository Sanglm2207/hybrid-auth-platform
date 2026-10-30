package dev.kaidev.auth.identity;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.security.*;
import dev.kaidev.common.servlet.support.ServletApi;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
public class InternalIdentityController {
    public record ProfileAccess(@Valid @jakarta.validation.constraints.NotNull IdentityCheck identity,
            @jakarta.validation.constraints.NotNull java.util.UUID target,java.util.UUID tenant,
            @jakarta.validation.constraints.Pattern(regexp="read|update") @jakarta.validation.constraints.NotNull String action) {}
    private final dev.kaidev.auth.access.TenantPolicy policy;
    @PostMapping("/internal/identity/authorize-profile")
    public ApiResponse<java.util.Map<String,Boolean>> profile(@Valid @RequestBody ProfileAccess request){
        return ServletApi.success(CommonCode.OK,java.util.Map.of("allowed",policy.profile(request.identity(),request.target(),request.tenant(),request.action())));
    }
    private final IdentityValidationService identities;
    public InternalIdentityController(IdentityValidationService identities,dev.kaidev.auth.access.TenantPolicy policy) { this.identities = identities;this.policy=policy; }
    @PostMapping("/internal/identity/check")
    public ApiResponse<IdentityAccess> check(@Valid @RequestBody IdentityCheck request) {
        return ServletApi.success(CommonCode.OK, identities.check(request));
    }
}
