package dev.kaidev.user.controller;

import dev.kaidev.user.service.ProfileService;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.servlet.support.ServletApi;
import java.util.*;
import org.springframework.web.bind.annotation.*;

/** The separate /internal/** security chain requires the service key; Gateway has no route here. */
@RestController
@RequestMapping("/internal/users/{id}/profile")
public class InternalProfileController {
    private final ProfileService profiles;
    public InternalProfileController(ProfileService profiles){this.profiles=profiles;}
    @GetMapping public ApiResponse<?> export(@PathVariable UUID id){return ServletApi.success(CommonCode.OK,profiles.me(id,List.of()));}
    @DeleteMapping public ApiResponse<?> delete(@PathVariable UUID id){profiles.erase(id);return ServletApi.success(CommonCode.OK,null);}
}
