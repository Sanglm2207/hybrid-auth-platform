package dev.kaidev.auth.integration;

import dev.kaidev.auth.client.MailServiceClient;
import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.*;
import dev.kaidev.auth.security.*;
import dev.kaidev.auth.service.SessionService;
import dev.kaidev.common.exception.ApiException;
import java.nio.file.*;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.*;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {"app.jwt.key-set=", "app.account.recovery-workers=1",
        "spring.datasource.url=jdbc:h2:mem:account-http;DB_CLOSE_DELAY=-1", "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa", "spring.datasource.password="})
@AutoConfigureMockMvc
class AccountLifecycleHttpTest {
    private static final String BASE = "/api/v1/auth", CURRENT = "CurrentPassword123!", NEXT = "NewPassword456!";
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired UserRepository users;
    @Autowired AccountActionTokenRepository tokens;
    @Autowired PasswordEncoder passwords;
    @Autowired JwtKeyRing keys;
    @Autowired dev.kaidev.auth.outbox.OutboxWorker worker;
    @MockitoBean MailServiceClient mail;
    @MockitoBean SessionService sessions;
    @MockitoBean dev.kaidev.auth.identity.IdentityValidationService identities;

    @BeforeEach void identityAccess() {
        when(identities.check(any())).thenReturn(new dev.kaidev.common.security.IdentityAccess(true, java.util.Set.of("USER"), dev.kaidev.auth.identity.Permissions.ALL));
    }
    @MockitoBean AbuseProtection protection;
    private static Path directory;
    private AppUser user;

    @DynamicPropertySource static void rsa(DynamicPropertyRegistry properties) throws Exception {
        directory = Files.createTempDirectory("account-http-keys-");
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); var pair = generator.generateKeyPair();
        Path privateKey = directory.resolve("private.pem"), publicKey = directory.resolve("public.pem");
        Files.writeString(privateKey, "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----");
        Files.writeString(publicKey, "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----");
        properties.add("app.private-key", privateKey::toString); properties.add("app.public-key", publicKey::toString);
    }
    @AfterAll static void cleanupKeys() throws Exception {
        if (directory != null) { Files.deleteIfExists(directory.resolve("private.pem")); Files.deleteIfExists(directory.resolve("public.pem")); Files.deleteIfExists(directory); }
    }
    @BeforeEach void setup() {
        user = new AppUser("owner@example.com", passwords.encode(CURRENT)); user.emailVerified = true; user = users.saveAndFlush(user);
    }
    @AfterEach void cleanup() throws Exception {
        drain(); tokens.deleteAll(); users.deleteAll();
    }
    private void drain() throws Exception { while (worker.processNext()) {} }
    private String jwt() {
        Instant now = Instant.now();
        return keys.encode(JwtEncoderParameters.from(JwtClaimsSet.builder().issuer("http://localhost:8701")
                .subject(user.id.toString()).claim("sid", UUID.randomUUID().toString()).claim("cv", 0L).claim("sv", 0L).audience(List.of("hybrid-api")).issuedAt(now).expiresAt(now.plusSeconds(900)).build())).getTokenValue();
    }
    private String token(String template, String variable) {
        return mockingDetails(mail).getInvocations().stream().filter(i -> template.equals(i.getArgument(1))).reduce((a,b) -> b)
                .map(i -> { Map<String,String> values = i.getArgument(2); return values.get(variable); }).orElseThrow();
    }

    @Test void forgotResponsesAreUniformAndResetDoesNotAutoLogin() throws Exception {
        for (String email : List.of("missing@example.com", user.email)) {
            String response = mvc.perform(post(BASE + "/forgot-password").contentType(MediaType.APPLICATION_JSON)
                    .content(mapper.writeValueAsString(Map.of("email", email))))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("PASSWORD_RESET_REQUESTED"))
                    .andExpect(jsonPath("$.data").isEmpty()).andReturn().getResponse().getContentAsString();
            assertThat(response).doesNotContain(email, "resetToken", "accessToken");
        }
        drain(); String raw = token("password-reset", "resetToken");
        String response = mvc.perform(post(BASE + "/reset-password").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("token", raw, "newPassword", NEXT))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("PASSWORD_RESET"))
                .andReturn().getResponse().getContentAsString();
        assertThat(response).doesNotContain(raw, NEXT, "accessToken"); verify(sessions).revokeAll(user.id);
        mvc.perform(post(BASE + "/reset-password").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("token", raw, "newPassword", NEXT))))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_ACCOUNT_TOKEN"));
    }
    @Test void knownAccountMailFailureStillGetsGenericForgotResponseAndRollsBackToken() throws Exception {
        doThrow(new ApiException(AuthCode.EMAIL_DELIVERY_FAILED)).when(mail).send(anyString(), eq("password-reset"), anyMap());
        mvc.perform(post(BASE + "/forgot-password").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("email", user.email))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("PASSWORD_RESET_REQUESTED"));
        drain(); assertThat(tokens.count()).isZero(); assertThat(users.findById(user.id).orElseThrow().passwordResetResendAt).isNull();
    }
    @ParameterizedTest @ValueSource(strings = {"/change-password", "/change-email"})
    void protectedChangesRequireJwt(String path) throws Exception {
        mvc.perform(post(BASE + path).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
        verifyNoInteractions(mail, sessions);
    }
    @Test void changePasswordUsesJwtSubjectAndRequiresTheCurrentPassword() throws Exception {
        String bearer = jwt();
        mvc.perform(post(BASE + "/change-password").header("Authorization", "Bearer " + bearer).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("currentPassword", "wrong", "newPassword", NEXT))))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        mvc.perform(post(BASE + "/change-password").header("Authorization", "Bearer " + bearer).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("currentPassword", CURRENT, "newPassword", NEXT, "userId", UUID.randomUUID().toString()))))
                .andExpect(status().isBadRequest());
        mvc.perform(post(BASE + "/change-password").header("Authorization", "Bearer " + bearer).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("currentPassword", CURRENT, "newPassword", NEXT))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("PASSWORD_CHANGED"));
        assertThat(passwords.matches(NEXT, users.findById(user.id).orElseThrow().passwordHash)).isTrue();
        verify(sessions).revokeAll(user.id);
    }
    @Test void newEmailMustBeConfirmedWithItsOpaqueTokenAndNoJwtIsRequiredToConfirm() throws Exception {
        mvc.perform(post(BASE + "/change-email").header("Authorization", "Bearer " + jwt()).contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("currentPassword", CURRENT, "newEmail", " NEW@EXAMPLE.COM "))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("EMAIL_CHANGE_REQUESTED"));
        assertThat(users.findById(user.id).orElseThrow().email).isEqualTo(user.email);
        String raw = token("email-change-verification", "verificationToken");
        mvc.perform(post(BASE + "/confirm-email-change").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("token", raw))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("EMAIL_CHANGED"));
        assertThat(users.findById(user.id).orElseThrow().email).isEqualTo("new@example.com");
        verify(sessions).revokeAll(user.id);
    }
    @ParameterizedTest @ValueSource(strings = {"/resend-otp", "/resend-verification"})
    void existingVerificationResendAndAliasRemainPublic(String path) throws Exception {
        mvc.perform(post(BASE + path).contentType(MediaType.APPLICATION_JSON).content("{\"email\":\"missing@example.com\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("OTP_REQUESTED"));
    }
    @Test void accessJwtIsNotAcceptedAsAResetProofAndWeakPasswordIsRejected() throws Exception {
        mvc.perform(post(BASE + "/reset-password").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("token", jwt(), "newPassword", NEXT))))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
        mvc.perform(post(BASE + "/reset-password").contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("token", "a".repeat(43), "newPassword", "short"))))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
        verifyNoInteractions(sessions);
    }
    @ParameterizedTest @ValueSource(strings = {"/forgot-password", "/reset-password", "/confirm-email-change"})
    void malformedPublicFormsUseTheSharedValidationEnvelope(String path) throws Exception {
        mvc.perform(post(BASE + path).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    }
}
