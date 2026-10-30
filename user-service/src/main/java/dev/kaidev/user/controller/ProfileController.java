package dev.kaidev.user.controller;

import dev.kaidev.common.api.ApiPaths;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.servlet.support.ServletApi;
import dev.kaidev.common.security.SecurityAudit;
import dev.kaidev.user.dto.request.UpdateProfileRequest;
import dev.kaidev.user.dto.response.ProfileResponse;
import dev.kaidev.user.service.ProfileService;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(ApiPaths.USERS_V1)
public class ProfileController {
    @org.springframework.beans.factory.annotation.Autowired private dev.kaidev.user.security.UserIdentityClient identities;
    private final ProfileService profiles;
    public ProfileController(ProfileService profiles) { this.profiles = profiles; }
    @GetMapping("/me")
    public ApiResponse<ProfileResponse> me(@AuthenticationPrincipal Jwt jwt) {
        return ServletApi.success(CommonCode.OK, profiles.me(UUID.fromString(jwt.getSubject()), jwt.getClaimAsStringList("roles")));
    }
    @PatchMapping("/me")
    public ApiResponse<ProfileResponse> patch(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody UpdateProfileRequest request) {
        var response = profiles.patch(UUID.fromString(jwt.getSubject()), jwt.getClaimAsStringList("roles"), request);
        SecurityAudit.record(SecurityAudit.Event.PROFILE_UPDATED, SecurityAudit.Outcome.SUCCESS, jwt.getSubject(), ServletApi.traceId());
        return ServletApi.success(CommonCode.OK, response);
    }
    @GetMapping("/{id:[0-9a-fA-F-]{36}}")
    public ApiResponse<ProfileResponse> read(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@RequestParam(required=false)UUID tenantId){
        identities.authorizeProfile(dev.kaidev.common.security.IdentityCheck.fromClaims(jwt.getClaims()),id,tenantId,"read",ServletApi.traceId());
        return ServletApi.success(CommonCode.OK,profiles.me(id,java.util.List.of()));
    }
    @PatchMapping("/{id:[0-9a-fA-F-]{36}}")
    public ApiResponse<ProfileResponse> update(@AuthenticationPrincipal Jwt jwt,@PathVariable UUID id,@RequestParam(required=false)UUID tenantId,
            @Valid @RequestBody UpdateProfileRequest body){
        identities.authorizeProfile(dev.kaidev.common.security.IdentityCheck.fromClaims(jwt.getClaims()),id,tenantId,"update",ServletApi.traceId());
        var updated=profiles.patch(id,java.util.List.of(),body);
        SecurityAudit.record(SecurityAudit.Event.PROFILE_UPDATED,SecurityAudit.Outcome.SUCCESS,jwt.getSubject(),ServletApi.traceId(),java.util.Map.of("targetUserId",id));
        return ServletApi.success(CommonCode.OK,updated);
    }
}
