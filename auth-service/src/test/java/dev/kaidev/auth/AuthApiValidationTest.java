package dev.kaidev.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.server.ResponseStatusException;

class AuthApiValidationTest {
    private final EmailVerificationService verification = mock(EmailVerificationService.class);
    private MockMvc mvc;

    @BeforeEach
    void setup() {
        mvc = MockMvcBuilders.standaloneSetup(new AuthController(null, null, null, null, verification))
                .setControllerAdvice(new ApiExceptionHandler()).build();
    }

    @Test
    void shortPasswordReturnsActionableMessageWithoutEchoingPassword() throws Exception {
        String body = mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"test@example.com\",\"password\":\"Short123!\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").value("Password must contain at least 12 characters"))
                .andReturn().getResponse().getContentAsString();
        assertThat(body).doesNotContain("Short123!");
        verifyNoInteractions(verification);
    }

    @Test
    void smtpFailureIncludesSafeReasonInResponse() throws Exception {
        when(verification.register("test@example.com", "StrongPassword123!"))
                .thenThrow(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                        "Email delivery is not configured"));
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"test@example.com\",\"password\":\"StrongPassword123!\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.detail").value("Email delivery is not configured"));
    }
}
