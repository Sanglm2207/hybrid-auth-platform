package dev.kaidev.user.integration;

import dev.kaidev.common.servlet.config.ServletApiConfiguration;
import dev.kaidev.user.config.UserSecurity;
import dev.kaidev.user.controller.ProfileController;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(ProfileController.class)
@Import(UserSecurity.class)
@ImportAutoConfiguration(ServletApiConfiguration.class)
class ProfileHttpContractTest {
    @Autowired MockMvc mvc;
    @MockitoBean JwtDecoder decoder;

    @BeforeEach void setup() {
        when(decoder.decode("valid-token")).thenReturn(Jwt.withTokenValue("valid-token").header("alg", "RS256")
                .subject("user-123").claim("roles", List.of("USER")).build());
        when(decoder.decode("invalid-token")).thenThrow(new BadJwtException("test decoder rejection"));
    }

    @Test void authenticatedProfileUsesSharedResponse() throws Exception {
        mvc.perform(get("/users/me").header("Authorization", "Bearer valid-token"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.code").value("OK")).andExpect(jsonPath("$.data.id").value("user-123"))
                .andExpect(jsonPath("$.data.roles[0]").value("USER"));
    }

    @Test void missingOrInvalidTokenUsesSharedError() throws Exception {
        mvc.perform(get("/users/me")).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.success").value(false)).andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
        mvc.perform(get("/users/me").header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    @Test void unknownAuthenticatedRouteUsesSharedNotFound() throws Exception {
        mvc.perform(get("/users/missing").header("Authorization", "Bearer valid-token"))
                .andExpect(status().isNotFound()).andExpect(jsonPath("$.code").value("NOT_FOUND"));
    }
}
