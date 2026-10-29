package dev.kaidev.user.controller;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.servlet.support.ServletApi;
import dev.kaidev.user.dto.response.ProfileResponse;

import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class ProfileController {
    @GetMapping("/me")
    public ApiResponse<ProfileResponse> me(@AuthenticationPrincipal Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        return ServletApi.success(CommonCode.OK, new ProfileResponse(jwt.getSubject(), roles == null ? List.of() : roles));
    }
}
