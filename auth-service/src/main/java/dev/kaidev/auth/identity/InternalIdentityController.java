package dev.kaidev.auth.identity;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.security.*;
import dev.kaidev.common.servlet.support.ServletApi;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
public class InternalIdentityController {
    private final IdentityValidationService identities;
    public InternalIdentityController(IdentityValidationService identities) { this.identities = identities; }
    @PostMapping("/internal/identity/check")
    public ApiResponse<IdentityAccess> check(@Valid @RequestBody IdentityCheck request) {
        return ServletApi.success(CommonCode.OK, identities.check(request));
    }
}
