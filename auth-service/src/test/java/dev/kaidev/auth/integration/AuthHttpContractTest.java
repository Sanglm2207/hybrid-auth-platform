package dev.kaidev.auth.integration;

import dev.kaidev.auth.dto.response.TokenResponse;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.service.SessionService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.*;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:auth-http;DB_CLOSE_DELAY=-1", "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa", "spring.datasource.password=", "spring.mail.host=smtp.test", "app.email-from=sender@example.com"})
@AutoConfigureMockMvc
class AuthHttpContractTest {
    @Autowired MockMvc mvc;
    @Autowired UserRepository users;
    @Autowired ObjectMapper mapper;
    @MockitoBean JavaMailSender mail;
    @MockitoBean SessionService sessions;
    private static Path directory;

    @DynamicPropertySource
    static void keys(DynamicPropertyRegistry properties) throws Exception {
        directory = Files.createTempDirectory("auth-contract-keys-");
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var pair = generator.generateKeyPair();
        Path privateKey = directory.resolve("private.pem"), publicKey = directory.resolve("public.pem");
        Files.writeString(privateKey, "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----");
        Files.writeString(publicKey, "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----");
        properties.add("app.private-key", () -> privateKey.toString());
        properties.add("app.public-key", () -> publicKey.toString());
    }

    @AfterAll static void deleteKeys() throws Exception {
        if (directory != null) {
            Files.deleteIfExists(directory.resolve("private.pem"));
            Files.deleteIfExists(directory.resolve("public.pem"));
            Files.deleteIfExists(directory);
        }
    }
    @AfterEach void cleanUp() { users.deleteAll(); }

    static Stream<Arguments> invalidForms() {
        return Stream.of(
                Arguments.of("/api/v1/auth/register", "{}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/register", "{\"email\":null,\"password\":null}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/register", "{\"email\":\"bad\",\"password\":\"short\"}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/register", "{\"email\":\"a@example.com\",\"password\":\"" + "a".repeat(73) + "\"}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/register", "{\"email\":\"a@example.com\",\"password\":\"" + "界".repeat(25) + "\"}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/register", "{\"email\":123,\"password\":false}", "INVALID_REQUEST"),
                Arguments.of("/api/v1/auth/register", "{\"email\":\"a@example.com\",\"password\":\"StrongPassword123!\",\"role\":\"ADMIN\"}", "INVALID_REQUEST"),
                Arguments.of("/api/v1/auth/register", "{\"email\":\"a@example.com\",\"email\":\"b@example.com\"}", "INVALID_REQUEST"),
                Arguments.of("/api/v1/auth/register", "{\"email\":", "INVALID_REQUEST"),
                Arguments.of("/api/v1/auth/register", "null", "INVALID_REQUEST"),
                Arguments.of("/api/v1/auth/register", "[]", "INVALID_REQUEST"),
                Arguments.of("/api/v1/auth/register", "{} {}", "INVALID_REQUEST"),
                Arguments.of("/api/v1/auth/login", "{\"email\":\"bad\",\"password\":\"\"}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/login", "{\"email\":\"a@example.com\",\"password\":\"" + "界".repeat(25) + "\"}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/verify-email", "{\"email\":\"a@example.com\",\"otp\":\"12345\"}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/verify-email", "{\"email\":\"a@example.com\",\"otp\":123456}", "INVALID_REQUEST"),
                Arguments.of("/api/v1/auth/verify-email", "{\"email\":\"a@example.com\",\"otp\":\"12a456\"}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/verify-email", "{}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/resend-otp", "{\"email\":\" \"}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/resend-otp", "{\"email\":\"" + "a".repeat(250) + "@example.com\"}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/refresh", "{}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/refresh", "{\"refreshToken\":\"invalid\"}", "VALIDATION_FAILED"),
                Arguments.of("/api/v1/auth/logout", "{\"refreshToken\":null}", "VALIDATION_FAILED"));
    }

    @ParameterizedTest @MethodSource("invalidForms")
    void rejectsInvalidFormsWithSharedContract(String path, String json, String code) throws Exception {
        mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.code").value(code)).andExpect(jsonPath("$.message").isNotEmpty())
                .andExpect(jsonPath("$.errors").isArray()).andExpect(jsonPath("$.traceId").isNotEmpty())
                .andExpect(jsonPath("$.timestamp").isNotEmpty());
        verifyNoInteractions(mail, sessions);
    }

    @Test void emptyBodyAndUnsupportedMediaAreNormalized() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.TEXT_PLAIN).content("body"))
                .andExpect(status().isUnsupportedMediaType()).andExpect(jsonPath("$.code").value("UNSUPPORTED_MEDIA_TYPE"));
        mvc.perform(get("/api/v1/auth/register")).andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.code").value("METHOD_NOT_ALLOWED"));
    }

    @Test void registrationVerificationLoginAndLogoutShareContract() throws Exception {
        mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\" TEST@EXAMPLE.COM \",\"password\":\"StrongPassword123!\"}"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.code").value("REGISTERED"))
                .andExpect(jsonPath("$.success").value(true)).andExpect(jsonPath("$.data.email").value("test@example.com"))
                .andExpect(jsonPath("$.data.emailVerified").value(false));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"test@example.com\",\"password\":\"StrongPassword123!\"}"))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("EMAIL_NOT_VERIFIED"));
        ArgumentCaptor<SimpleMailMessage> message = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mail).send(message.capture());
        String otp = message.getValue().getText().split(": ")[1].substring(0, 6);
        mvc.perform(post("/api/v1/auth/verify-email").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"test@example.com\",\"otp\":\"" + otp + "\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("EMAIL_VERIFIED"));
        when(sessions.issue(any(AppUser.class))).thenReturn(new TokenResponse("test-access", "test-refresh", "Bearer", 900));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"test@example.com\",\"password\":\"StrongPassword123!\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("LOGGED_IN"))
                .andExpect(jsonPath("$.data.accessToken").value("test-access"));
        mvc.perform(post("/api/v1/auth/logout").contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + "a".repeat(43) + "\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("LOGGED_OUT"));
    }

    @Test void securityErrorsAndTraceHeadersShareContract() throws Exception {
        String trace = "12345678-1234-1234-1234-123456789abc";
        mvc.perform(get("/private").header("X-Request-Id", trace))
                .andExpect(status().isUnauthorized()).andExpect(header().string("X-Request-Id", trace))
                .andExpect(jsonPath("$.traceId").value(trace)).andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
        mvc.perform(get("/private").header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    @Test void unexpectedErrorsHideInternalMessages() throws Exception {
        when(sessions.rotate(anyString(), any())).thenThrow(new IllegalStateException("secret-internal-detail"));
        String body = mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + "a".repeat(43) + "\"}"))
                .andExpect(status().isInternalServerError()).andExpect(jsonPath("$.code").value("INTERNAL_ERROR"))
                .andReturn().getResponse().getContentAsString();
        assertThat(body).doesNotContain("secret-internal-detail", "stackTrace");
    }

    @Test void jwksRetainsStandardShape() throws Exception {
        mvc.perform(get("/.well-known/jwks.json")).andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray()).andExpect(jsonPath("$.success").doesNotExist());
    }
}
