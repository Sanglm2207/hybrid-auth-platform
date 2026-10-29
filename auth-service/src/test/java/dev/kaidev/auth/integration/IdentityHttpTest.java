package dev.kaidev.auth.integration;

import dev.kaidev.auth.client.MailServiceClient;
import dev.kaidev.auth.entity.*;
import dev.kaidev.auth.identity.*;
import dev.kaidev.auth.repository.*;
import dev.kaidev.auth.security.*;
import dev.kaidev.auth.service.*;
import dev.kaidev.common.security.ClientIdentity;
import java.nio.file.*;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import com.fasterxml.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {"app.jwt.key-set=", "app.identity.api-key=identity-test-key-at-least-thirty-two-characters",
        "spring.datasource.url=jdbc:h2:mem:p2-http;DB_CLOSE_DELAY=-1", "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa", "spring.datasource.password="})
@AutoConfigureMockMvc
class IdentityHttpTest {
    @Autowired MockMvc mvc;
    @Autowired UserRepository users;
    @Autowired AccountActionTokenRepository tokens;
    @Autowired DeviceRepository devices;
    @Autowired RoleRepository roles;
    @Autowired JwtKeyRing keys;
    @Autowired PasswordEncoder passwords;
    @Autowired ObjectMapper json;
    @Autowired IdentityManagementService management;
    @Autowired org.springframework.jdbc.core.JdbcTemplate jdbc;
    @MockitoBean MailServiceClient mail;
    @MockitoBean SessionService sessions;
    @MockitoBean AbuseProtection protection;
    private static Path directory;
    private static final String PASSWORD = "CurrentPassword123!", BASE = "/api/v1/auth";
    private AppUser owner, admin;
    private UUID family;
    @DynamicPropertySource static void rsa(DynamicPropertyRegistry properties) throws Exception {
        directory = Files.createTempDirectory("p2-http-keys-");
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); var pair = generator.generateKeyPair();
        Path priv = directory.resolve("private.pem"), pub = directory.resolve("public.pem");
        Files.writeString(priv, "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----");
        Files.writeString(pub, "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----");
        properties.add("app.private-key", priv::toString); properties.add("app.public-key", pub::toString);
    }
    @AfterAll static void cleanupKeys() throws Exception {
        if (directory != null) { Files.deleteIfExists(directory.resolve("private.pem")); Files.deleteIfExists(directory.resolve("public.pem")); Files.deleteIfExists(directory); }
    }
    @BeforeEach void setup() {
        owner = new AppUser("owner@example.com", passwords.encode(PASSWORD)); owner.emailVerified = true; owner = users.saveAndFlush(owner);
        admin = new AppUser("admin@example.com", passwords.encode(PASSWORD)); admin.emailVerified = true; admin.roles = new HashSet<>(Set.of("ADMIN")); admin = users.saveAndFlush(admin);
        family = UUID.randomUUID(); when(sessions.active(any(), any(), anyLong(), anyLong())).thenReturn(true);
        when(sessions.list(any(), any())).thenReturn(List.of());
    }
    @AfterEach void cleanup() { tokens.deleteAll(); devices.deleteAll(); users.deleteAll(); roles.findById("AUDITOR").ifPresent(roles::delete); }
    private String jwt(AppUser user) {
        return keys.encode(JwtEncoderParameters.from(JwtClaimsSet.builder().issuer("http://localhost:8701")
                .subject(user.id.toString()).claim("sid", family.toString()).claim("cv", user.credentialRevision).claim("sv", 0L)
                .claim("roles", List.of("USER")).audience(List.of("hybrid-api")).issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(900)).build())).getTokenValue();
    }
    @Test void identityCheckAllowsThrottledActivityWrites() throws Exception {
        when(sessions.active(any(),any(),anyLong(),anyLong())).thenAnswer(invocation->{
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive()).isTrue();
            assertThat(org.springframework.transaction.support.TransactionSynchronizationManager.isCurrentTransactionReadOnly()).isFalse();
            return true;
        });
        mvc.perform(get(BASE+"/sessions").header("Authorization","Bearer "+jwt(owner))).andExpect(status().isOk());
    }
    @Test void lastAdministratorCannotDemoteOrDeactivateSelf() throws Exception {
        mvc.perform(put(BASE+"/users/"+admin.id+"/roles").header("Authorization","Bearer "+jwt(admin))
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("roles",Set.of("USER"),"currentPassword",PASSWORD))))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("LAST_ADMINISTRATOR"));
        mvc.perform(post(BASE+"/deactivate").header("Authorization","Bearer "+jwt(admin))
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("currentPassword",PASSWORD))))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("LAST_ADMINISTRATOR"));
        assertThat(users.findById(admin.id).orElseThrow().active).isTrue();
    }
    @Test void concurrentAdminDemotionsCannotRemoveBothManagers() throws Exception {
        management.assignRoles(admin.id,owner.id,Set.of("ADMIN"),PASSWORD);
        var pool=java.util.concurrent.Executors.newFixedThreadPool(2);
        var start=new java.util.concurrent.CountDownLatch(1);
        try {
            var futures=List.of(admin.id,owner.id).stream().map(id->pool.submit(()->{
                start.await();try{management.assignRoles(id,id,Set.of("USER"),PASSWORD);return "OK";}
                catch(dev.kaidev.common.exception.ApiException e){return e.apiCode().name();}
            })).toList();start.countDown();
            var results=new ArrayList<String>();for(var f:futures)results.add(f.get(15,java.util.concurrent.TimeUnit.SECONDS));
            assertThat(results).containsExactlyInAnyOrder("OK","LAST_ADMINISTRATOR");
            assertThat(jdbc.queryForObject("select count(*) from app_users u join identity_user_roles r on u.id=r.user_id where u.active=true and r.role_name='ADMIN'",Integer.class)).isEqualTo(1);
        }finally{pool.shutdownNow();}
    }

    @Test void userCanOnlyListAndRevokeSessionsUnderTheirOwnSubject() throws Exception {
        mvc.perform(get(BASE + "/sessions").header("Authorization", "Bearer " + jwt(owner)).param("userId", admin.id.toString()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data").isArray());
        verify(sessions).list(owner.id, family);
        UUID target = UUID.randomUUID();
        mvc.perform(delete(BASE + "/sessions/" + target).header("Authorization", "Bearer " + jwt(owner)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("SESSION_REVOKED"));
        verify(sessions).revokeSession(owner.id, target);
    }
    @Test void deviceHistoryIsOwnedAndDeletingDeviceRevokesItsSessions() throws Exception {
        var device = new AuthDevice(); device.userId = owner.id; device.deviceId = UUID.randomUUID(); device.userAgent = "Browser";
        device.lastIp = "203.0.113.4"; device.firstSeenAt = Instant.now(); device.lastSeenAt = Instant.now(); devices.saveAndFlush(device);
        when(sessions.list(eq(owner.id), any())).thenReturn(List.of(new SessionView(family, device.deviceId, "Browser", device.lastIp,
                Instant.now(), Instant.now(), Instant.now().plusSeconds(1000), true)));
        mvc.perform(get(BASE + "/devices").header("Authorization", "Bearer " + jwt(owner)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data[0].id").value(device.deviceId.toString()));
        mvc.perform(delete(BASE + "/devices/" + device.deviceId).header("Authorization", "Bearer " + jwt(admin))).andExpect(status().isNotFound());
        mvc.perform(delete(BASE + "/devices/" + device.deviceId).header("Authorization", "Bearer " + jwt(owner))).andExpect(status().isOk());
        verify(sessions).revokeSession(owner.id, family); assertThat(devices.count()).isZero();
    }
    @Test void ordinaryUserCannotManageRolesEvenIfJwtClaimsAdmin() throws Exception {
        mvc.perform(get(BASE + "/roles").header("Authorization", "Bearer " + jwt(owner)))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
        mvc.perform(get(BASE + "/roles").header("Authorization", "Bearer " + jwt(admin))).andExpect(status().isOk());
    }
    @Test void administratorCanCreatePolicyAssignRolesAndInvalidateOldIdentityVersions() throws Exception {
        String old = jwt(owner);
        mvc.perform(post(BASE + "/roles").header("Authorization", "Bearer " + jwt(admin)).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("name", "AUDITOR", "permissions", Set.of("sessions:read", "profile:read"), "currentPassword", PASSWORD))))
                .andExpect(status().isOk());
        mvc.perform(put(BASE + "/users/" + owner.id + "/roles").header("Authorization", "Bearer " + jwt(admin)).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("roles", Set.of("AUDITOR"), "currentPassword", PASSWORD))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("ROLES_UPDATED"));
        verify(sessions).revokeAll(owner.id);
        mvc.perform(get(BASE + "/sessions").header("Authorization", "Bearer " + old)).andExpect(status().isUnauthorized());
        var current = users.findById(owner.id).orElseThrow();
        mvc.perform(get(BASE + "/sessions").header("Authorization", "Bearer " + jwt(current))).andExpect(status().isOk());
        mvc.perform(delete(BASE + "/sessions/" + UUID.randomUUID()).header("Authorization", "Bearer " + jwt(current))).andExpect(status().isForbidden());
    }
    @Test void invalidPermissionAndWrongAdminPasswordCannotMutatePolicy() throws Exception {
        for (Map<String,Object> body : List.<Map<String,Object>>of(
                Map.of("name", "AUDITOR", "permissions", Set.of("root:everything"), "currentPassword", PASSWORD),
                Map.of("name", "AUDITOR", "permissions", Set.of("profile:read"), "currentPassword", "WrongPassword123!"))) {
            mvc.perform(post(BASE + "/roles").header("Authorization", "Bearer " + jwt(admin)).contentType(MediaType.APPLICATION_JSON)
                    .content(json.writeValueAsString(body))).andExpect(result -> assertThat(result.getResponse().getStatus()).isIn(400,401));
        }
        assertThat(roles.findById("AUDITOR")).isEmpty();
    }
    @Test void deactivateNeedsPasswordDisablesLoginAndRejectsExistingJwt() throws Exception {
        String bearer = jwt(owner);
        mvc.perform(post(BASE + "/deactivate").header("Authorization", "Bearer " + bearer).contentType(MediaType.APPLICATION_JSON)
                .content("{\"currentPassword\":\"wrong\"}")).andExpect(status().isUnauthorized());
        mvc.perform(post(BASE + "/deactivate").header("Authorization", "Bearer " + bearer).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("currentPassword", PASSWORD))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("ACCOUNT_DEACTIVATED"));
        assertThat(users.findById(owner.id).orElseThrow().active).isFalse(); verify(sessions).revokeAll(owner.id);
        verify(mail).send(owner.email, "account-deactivated", Map.of());
        mvc.perform(get(BASE + "/sessions").header("Authorization", "Bearer " + bearer)).andExpect(status().isUnauthorized());
        mvc.perform(post(BASE + "/login").contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("email", owner.email, "password", PASSWORD))))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCOUNT_DISABLED"));
    }
    @Test void internalIdentityChecksRequireOneServiceKeyAndDoNotExposeInactiveRoles() throws Exception {
        String body = json.writeValueAsString(Map.of("subject", owner.id, "sessionId", family, "sessionVersion", 0, "credentialRevision", 0));
        mvc.perform(post("/internal/identity/check").contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isUnauthorized());
        mvc.perform(post("/internal/identity/check").header("X-Identity-Service-Key", "identity-test-key-at-least-thirty-two-characters")
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isOk()).andExpect(jsonPath("$.data.active").value(true));
        when(sessions.active(any(), any(), anyLong(), anyLong())).thenReturn(false);
        mvc.perform(post("/internal/identity/check").header("X-Identity-Service-Key", "identity-test-key-at-least-thirty-two-characters")
                .contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isOk()).andExpect(jsonPath("$.data.active").value(false))
                .andExpect(jsonPath("$.data.roles").isEmpty());
    }
}
