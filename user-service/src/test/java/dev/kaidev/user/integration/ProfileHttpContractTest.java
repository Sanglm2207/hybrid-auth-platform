package dev.kaidev.user.integration;

import dev.kaidev.common.security.*;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.user.security.UserIdentityClient;
import dev.kaidev.user.repository.ProfileRepository;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {"spring.datasource.url=jdbc:h2:mem:profile-http;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver", "spring.datasource.username=sa", "spring.datasource.password="})
@AutoConfigureMockMvc
class ProfileHttpContractTest {
    @Autowired MockMvc mvc;
    @Autowired ProfileRepository profiles;
    @MockitoBean JwtDecoder decoder;
    @MockitoBean UserIdentityClient identities;
    private static final String USER = "11111111-1111-4111-8111-111111111111";
    @BeforeEach void setup() {
        when(decoder.decode("valid-token")).thenReturn(Jwt.withTokenValue("valid-token").header("alg", "RS256")
                .subject(USER).claim("roles", List.of("USER")).claim("sid", UUID.randomUUID().toString()).claim("cv", 0L).claim("sv", 0L).build());
        when(decoder.decode("invalid-token")).thenThrow(new BadJwtException("test decoder rejection"));
        when(identities.check(any(), anyString())).thenReturn(new IdentityAccess(true, Set.of("USER"), Set.of("profile:read", "profile:write")));
    }
    @AfterEach void cleanup() { profiles.deleteAll(); }
    @Test void authenticatedProfileUsesSharedResponse() throws Exception {
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer valid-token"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.id").value(USER))
                .andExpect(jsonPath("$.data.roles[0]").value("USER")).andExpect(jsonPath("$.data.displayName").value(""));
    }
    @Test void patchPersistsOnlyOwnedProfileFieldsAndPreservesOmittedFields() throws Exception {
        mvc.perform(patch("/api/v1/users/me").header("Authorization", "Bearer valid-token").contentType(MediaType.APPLICATION_JSON)
                .content("{\"displayName\":\"Kai\",\"bio\":\"Hello\",\"locale\":\"vi-VN\",\"timeZone\":\"Asia/Ho_Chi_Minh\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.displayName").value("Kai"));
        mvc.perform(patch("/api/v1/users/me").header("Authorization", "Bearer valid-token").contentType(MediaType.APPLICATION_JSON).content("{\"bio\":\"\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.bio").value(""))
                .andExpect(jsonPath("$.data.displayName").value("Kai"));
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer valid-token"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.locale").value("vi-VN"));
    }
    @Test void missingOrInvalidTokenUsesSharedError() throws Exception {
        mvc.perform(get("/api/v1/users/me")).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer invalid-token")).andExpect(status().isUnauthorized());
    }
    @Test void revokedAccountIsDeniedAndIdentityOutageFailsClosed() throws Exception {
        when(identities.check(any(), anyString())).thenReturn(IdentityAccess.denied());
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer valid-token")).andExpect(status().isUnauthorized());
        when(identities.check(any(), anyString())).thenThrow(new ApiException(CommonCode.SERVICE_UNAVAILABLE));
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer valid-token"))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.code").value("SERVICE_UNAVAILABLE"));
    }
    @Test void livePermissionsAreEnforcedOnTheServiceItself() throws Exception {
        when(identities.check(any(), anyString())).thenReturn(new IdentityAccess(true, Set.of("USER"), Set.of("profile:read")));
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer valid-token")).andExpect(status().isOk());
        mvc.perform(patch("/api/v1/users/me").header("Authorization", "Bearer valid-token").contentType(MediaType.APPLICATION_JSON).content("{\"bio\":\"No\"}"))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
    }
    @Test void profileCannotChangeIdentityAndInvalidTimeZoneIsRejected() throws Exception {
        for (String body : new String[]{"{\"roles\":[\"ADMIN\"]}", "{\"userId\":\"another-user\"}", "{\"timeZone\":\"not/a/zone\"}"})
            mvc.perform(patch("/api/v1/users/me").header("Authorization", "Bearer valid-token").contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isBadRequest());
    }
    @Test void optionalVersionRejectsStaleWrites() throws Exception {
        mvc.perform(patch("/api/v1/users/me").header("Authorization", "Bearer valid-token").contentType(MediaType.APPLICATION_JSON).content("{\"displayName\":\"Kai\"}"))
                .andExpect(status().isOk());
        mvc.perform(patch("/api/v1/users/me").header("Authorization", "Bearer valid-token").contentType(MediaType.APPLICATION_JSON).content("{\"bio\":\"Changed\"}"))
                .andExpect(status().isOk());
        mvc.perform(patch("/api/v1/users/me").header("Authorization", "Bearer valid-token").contentType(MediaType.APPLICATION_JSON).content("{\"bio\":\"Stale\",\"version\":0}"))
                .andExpect(status().isConflict());
    }
    @Test void unknownAuthenticatedRouteUsesSharedNotFound() throws Exception {
        mvc.perform(get("/api/v1/users/missing").header("Authorization", "Bearer valid-token"))
                .andExpect(status().isNotFound()).andExpect(jsonPath("$.code").value("NOT_FOUND"));
    }
    @Test void profileResponseConformsToOpenApi() throws Exception {
        mvc.perform(get("/api/v1/users/me").header("Authorization", "Bearer valid-token"))
                .andExpect(status().isOk())
                .andExpect(com.atlassian.oai.validator.mockmvc.SwaggerValidatorMatchers.swagger().isValid("../docs/openapi.json"));
    }
    @Test void springSecurityTestCannotBypassLivePermissions() throws Exception {
        when(identities.check(any(), anyString())).thenReturn(new IdentityAccess(true, Set.of("USER"), Set.of()));
        mvc.perform(patch("/api/v1/users/me").with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt()
                    .jwt(j -> j.subject(USER).claim("sid", UUID.randomUUID().toString()).claim("cv",0L).claim("sv",0L)))
                .contentType(MediaType.APPLICATION_JSON).content("{\"bio\":\"denied\"}"))
                .andExpect(status().isForbidden());
    }
}
