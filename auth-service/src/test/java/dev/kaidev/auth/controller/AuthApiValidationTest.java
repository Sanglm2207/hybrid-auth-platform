package dev.kaidev.auth.controller;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.service.EmailVerificationService;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.servlet.exception.ServletExceptionHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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
                .setControllerAdvice(new ServletExceptionHandler()).build();
    }

    @Test
    void shortPasswordReturnsActionableMessageWithoutEchoingPassword() throws Exception {
        String body = mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"test@example.com\",\"password\":\"Short123!\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].message").value("Password must contain at least 12 characters and at most 72 UTF-8 bytes"))
                .andReturn().getResponse().getContentAsString();
        assertThat(body).doesNotContain("Short123!");
        verifyNoInteractions(verification);
    }

    @Test
    void smtpFailureIncludesSafeReasonInResponse() throws Exception {
        when(verification.register("test@example.com", "StrongPassword123!"))
                .thenThrow(new ApiException(AuthCode.EMAIL_NOT_CONFIGURED));
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"test@example.com\",\"password\":\"StrongPassword123!\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.message").value("Email delivery is not configured"));
    }
}
