package dev.kaidev.user.service;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.user.dto.request.UpdateProfileRequest;
import dev.kaidev.user.dto.response.ProfileResponse;
import dev.kaidev.user.entity.UserProfile;
import dev.kaidev.user.repository.ProfileRepository;
import java.time.*;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ProfileService {
    private final ProfileRepository profiles;
    public ProfileService(ProfileRepository profiles) { this.profiles = profiles; }
    @Transactional(readOnly = true)
    public ProfileResponse me(UUID user, List<String> roles) {
        var profile=profiles.findById(user).orElseGet(()->new UserProfile(user));requirePresent(profile);return response(profile,roles);
    }
    private void requirePresent(UserProfile profile){if(profile.deleted)throw new ApiException(CommonCode.NOT_FOUND);}
    @Transactional public void erase(UUID owner){
        var profile=profiles.findForUpdate(owner).orElseGet(()->new UserProfile(owner));
        profile.deleted=true;profile.displayName="";profile.bio="";profile.locale="en";profile.timeZone="UTC";profile.updatedAt=Instant.now();
        profiles.saveAndFlush(profile);
    }
    @Transactional
    public ProfileResponse patch(UUID user, List<String> roles, UpdateProfileRequest request) {
        var profile = profiles.findForUpdate(user).orElseGet(() -> new UserProfile(user));
        requirePresent(profile);
        long version = profile.version == null ? 0 : profile.version;
        if (request.version() != null && request.version() != version) throw new ApiException(CommonCode.CONFLICT);
        if (request.displayName() != null) profile.displayName = request.displayName();
        if (request.bio() != null) profile.bio = request.bio();
        try {
            if (request.locale() != null) profile.locale = new Locale.Builder().setLanguageTag(request.locale()).build().toLanguageTag();
            if (request.timeZone() != null) profile.timeZone = ZoneId.of(request.timeZone()).getId();
        } catch (IllformedLocaleException | DateTimeException e) { throw new ApiException(CommonCode.INVALID_REQUEST); }
        profile.updatedAt = Instant.now(); profile = profiles.saveAndFlush(profile);
        return response(profile, roles);
    }
    private ProfileResponse response(UserProfile profile, List<String> roles) {
        return new ProfileResponse(profile.userId.toString(), roles == null ? List.of() : List.copyOf(roles),
                profile.displayName, profile.bio, profile.locale, profile.timeZone, profile.version == null ? null : profile.updatedAt, profile.version == null ? 0 : profile.version);
    }
}
