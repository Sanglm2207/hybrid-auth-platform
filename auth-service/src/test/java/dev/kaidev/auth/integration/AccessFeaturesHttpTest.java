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
        "spring.datasource.url=jdbc:h2:mem:access-http;DB_CLOSE_DELAY=-1", "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa", "spring.datasource.password="})
@AutoConfigureMockMvc
class AccessFeaturesHttpTest {
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
        directory = Files.createTempDirectory("access-http-keys-");
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); var pair = generator.generateKeyPair();
        Path priv = directory.resolve("private.pem"), pub = directory.resolve("public.pem");
        Files.writeString(priv, "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----");
        Files.writeString(pub, "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----");
        properties.add("app.private-key", priv::toString); properties.add("app.public-key", pub::toString);
    }
    @AfterAll static void cleanupKeys() throws Exception {
        if (directory != null) { Files.deleteIfExists(directory.resolve("private.pem")); Files.deleteIfExists(directory.resolve("public.pem")); Files.deleteIfExists(directory); }
    }
    @MockitoBean dev.kaidev.auth.access.ProfileDataClient profileData;
    @Autowired dev.kaidev.auth.access.DeletionWorker deletionWorker;
    @Autowired dev.kaidev.auth.access.ServiceCredentials credentials;
    @Autowired dev.kaidev.auth.access.TenantPolicy tenants;
    @Autowired dev.kaidev.auth.access.LoginHistory history;
    @Autowired DeviceRegistry registry;
    @Autowired dev.kaidev.auth.outbox.AuthOutbox outbox;
    @BeforeEach void setup() {
        owner = new AppUser("owner@example.com", passwords.encode(PASSWORD)); owner.emailVerified = true; owner = users.saveAndFlush(owner);
        admin = new AppUser("admin@example.com", passwords.encode(PASSWORD)); admin.emailVerified = true; admin.roles = new HashSet<>(Set.of("ADMIN")); admin = users.saveAndFlush(admin);
        family = UUID.randomUUID(); when(sessions.active(any(), any(), anyLong(), anyLong())).thenReturn(true);
        when(sessions.list(any(), any())).thenReturn(List.of());
    }
    @AfterEach void cleanup() {
        for(String table:List.of("account_deletions","identity_tenant_members","identity_tenants","identity_api_keys","authentication_history","identity_refresh_ledger","identity_sessions","auth_outbox"))jdbc.update("delete from "+table);
        tokens.deleteAll(); devices.deleteAll(); users.deleteAll(); roles.findById("AUDITOR").ifPresent(roles::delete); }
    private String jwt(AppUser user) {
        return keys.encode(JwtEncoderParameters.from(JwtClaimsSet.builder().issuer("http://localhost:8701")
                .subject(user.id.toString()).claim("sid", family.toString()).claim("cv", user.credentialRevision).claim("sv", 0L)
                .claim("roles", List.of("USER")).audience(List.of("hybrid-api")).issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(900)).build())).getTokenValue();
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request(String method,String path,AppUser actor,Object body) throws Exception {
        var builder=org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request(org.springframework.http.HttpMethod.valueOf(method),path.startsWith("/api/")?path:BASE+path);
        if(actor!=null)builder.header("Authorization","Bearer "+jwt(actor));
        if(body!=null)builder.contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body));return builder;
    }
    @Test void actionPermissionsProtectAdminSearchAndDoNotExposeCredentials() throws Exception {
        mvc.perform(request("GET","/users",owner,null)).andExpect(status().isForbidden());
        String result=mvc.perform(request("GET","/users",admin,null).param("q","owner@"))
                .andExpect(status().isOk()).andExpect(com.atlassian.oai.validator.mockmvc.SwaggerValidatorMatchers.swagger().isValid("../docs/openapi.json"))
                .andExpect(jsonPath("$.data.length()").value(1))
                .andExpect(jsonPath("$.data[0].id").value(owner.id.toString())).andReturn().getResponse().getContentAsString();
        assertThat(result).doesNotContain("passwordHash","emailOtpHash",PASSWORD);
        mvc.perform(request("GET","/users",admin,null).param("page","-1")).andExpect(status().isBadRequest());
        mvc.perform(request("GET","/users",admin,null).param("size","101")).andExpect(status().isBadRequest());
    }
    @Test void adminLockAndUnlockRevokeCredentialsAndCannotRestoreOldJwt() throws Exception {
        String old=jwt(owner);
        mvc.perform(request("PATCH","/users/"+owner.id+"/status",admin,Map.of("status","SUSPENDED","currentPassword",PASSWORD)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.locked").value(true));
        mvc.perform(get(BASE+"/sessions").header("Authorization","Bearer "+old)).andExpect(status().isUnauthorized());
        mvc.perform(request("POST","/login",null,Map.of("email",owner.email,"password",PASSWORD))).andExpect(status().isForbidden());
        mvc.perform(request("GET","/users",admin,null).param("locked","true")).andExpect(jsonPath("$.data.length()").value(1));
        mvc.perform(request("PATCH","/users/"+owner.id+"/status",admin,Map.of("status","ENABLED","currentPassword",PASSWORD))).andExpect(status().isOk());
        mvc.perform(get(BASE+"/sessions").header("Authorization","Bearer "+old)).andExpect(status().isUnauthorized());
        verify(sessions,times(2)).revokeAll(owner.id);
    }
    @Test void statusNeedsReauthenticationAndPreservesLastAdministrator() throws Exception {
        mvc.perform(request("PATCH","/users/"+owner.id+"/status",admin,Map.of("status","SUSPENDED","currentPassword","wrong"))).andExpect(status().isUnauthorized());
        assertThat(users.findById(owner.id).orElseThrow().adminLocked).isFalse();
        mvc.perform(request("PATCH","/users/"+admin.id+"/status",admin,Map.of("status","SUSPENDED","currentPassword",PASSWORD)))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("LAST_ADMINISTRATOR"));
    }
    @Test void machineKeyIsReturnedOnceScopedAndImmediatelyRevocable() throws Exception {
        var issued=credentials.create(owner.id,"report-worker",Set.of("profile:read"),Instant.now().plusSeconds(3600),PASSWORD);
        assertThat(issued.secret()).startsWith("hap_");
        String stored=jdbc.queryForObject("select secret_hash from identity_api_keys where id=?",String.class,issued.key().id());
        assertThat(stored).doesNotContain(issued.secret());
        mvc.perform(request("GET","/api-keys",owner,null)).andExpect(status().isOk()).andExpect(jsonPath("$.data[0].name").value("report-worker"))
                .andExpect(result->assertThat(result.getResponse().getContentAsString()).doesNotContain(issued.secret(),stored));
        var response=mvc.perform(post(BASE+"/service-tokens").header("X-Api-Key",issued.secret())).andExpect(status().isOk())
                .andExpect(com.atlassian.oai.validator.mockmvc.SwaggerValidatorMatchers.swagger().isValid("../docs/openapi.json")).andReturn().getResponse();
        var machine=json.readTree(response.getContentAsString()).path("data");
        assertThat(machine.path("expiresIn").asInt()).isBetween(1,300);
        String bearer=machine.path("accessToken").asText();
        mvc.perform(get(BASE+"/api-keys").header("Authorization","Bearer "+bearer)).andExpect(status().isForbidden());
        mvc.perform(get(BASE+"/sessions").header("Authorization","Bearer "+bearer)).andExpect(status().isForbidden());
        mvc.perform(request("DELETE","/api-keys/"+issued.key().id(),admin,null)).andExpect(status().isNotFound());
        mvc.perform(request("DELETE","/api-keys/"+issued.key().id(),owner,null)).andExpect(status().isOk());
        mvc.perform(get(BASE+"/sessions").header("Authorization","Bearer "+bearer)).andExpect(status().isUnauthorized());
        mvc.perform(post(BASE+"/service-tokens").header("X-Api-Key",issued.secret())).andExpect(status().isUnauthorized());
    }
    @Test void keyCreationRejectsEscalationExpiryAndIncorrectPassword() throws Exception {
        for(Set<String> scopes:List.of(Set.of("roles:manage"),Set.of("users:read")))
            mvc.perform(request("POST","/api-keys",owner,Map.of("name","worker","scopes",scopes,"expiresAt",Instant.now().plusSeconds(300).toString(),"currentPassword",PASSWORD)))
                    .andExpect(status().isBadRequest());
        mvc.perform(request("POST","/api-keys",owner,Map.of("name","worker","scopes",Set.of("profile:read"),"expiresAt",Instant.now().minusSeconds(1).toString(),"currentPassword",PASSWORD))).andExpect(status().isBadRequest());
        mvc.perform(request("POST","/api-keys",owner,Map.of("name","worker","scopes",Set.of("profile:read"),"expiresAt",Instant.now().plusSeconds(300).toString(),"currentPassword","wrong"))).andExpect(status().isUnauthorized());
        mvc.perform(post(BASE+"/service-tokens").header("X-Api-Key","hap_invalid")).andExpect(status().isUnauthorized());
        assertThat(jdbc.queryForObject("select count(*) from identity_api_keys",Integer.class)).isZero();
    }
    @Test void keyExpiryLogoutAndLivePermissionRemovalDenyMachineAccess() throws Exception {
        var issued=credentials.create(owner.id,"worker",Set.of("profile:write"),Instant.now().plusSeconds(3600),PASSWORD);
        var token=credentials.exchange(issued.secret());
        var check=new dev.kaidev.common.security.IdentityCheck(owner.id,issued.key().id(),0L,0L);
        assertThat(tenants.profile(check,owner.id,null,"update")).isTrue();
        Set<String> original=Set.copyOf(jdbc.queryForList("select permission from identity_role_permissions where role_name=\'USER\'",String.class));
        try {
            management.saveRole(admin.id,"USER",Set.of("profile:read","keys:manage"),PASSWORD,false);
            assertThat(tenants.profile(check,owner.id,null,"update")).isFalse();
        }finally { management.saveRole(admin.id,"USER",original,PASSWORD,false); }
        jdbc.update("update identity_api_keys set expires_at=? where id=?",java.sql.Timestamp.from(Instant.now().minusSeconds(1)),issued.key().id());
        mvc.perform(post(BASE+"/service-tokens").header("X-Api-Key",issued.secret())).andExpect(status().isUnauthorized());
        jdbc.update("update identity_api_keys set expires_at=?,session_generation=99 where id=?",java.sql.Timestamp.from(Instant.now().plusSeconds(600)),issued.key().id());
        mvc.perform(post(BASE+"/service-tokens").header("X-Api-Key",issued.secret())).andExpect(status().isUnauthorized());
    }
    @Test void introspectionChecksRealJwtAndHidesOtherOwners() throws Exception {
        mvc.perform(request("POST","/introspect",owner,Map.of("token",jwt(owner)))).andExpect(status().isOk()).andExpect(jsonPath("$.data.active").value(true));
        mvc.perform(request("POST","/introspect",owner,Map.of("token",jwt(admin)))).andExpect(jsonPath("$.data.active").value(false));
        mvc.perform(request("POST","/introspect",owner,Map.of("token","forged-token"))).andExpect(jsonPath("$.data.active").value(false));
        mvc.perform(request("POST","/introspect",owner,Map.of("token","a".repeat(43)))).andExpect(jsonPath("$.data.active").value(false));
    }
    @Test void trustedDeviceRequiresOwnershipPasswordAndExpires() throws Exception {
        var id=UUID.randomUUID();registry.observe(owner.id,new DeviceInfo(id,"127.0.0.1","Browser"));
        verify(mail).send(owner.email,"new-device-login",Map.of());
        registry.observe(owner.id,new DeviceInfo(id,"127.0.0.1","Browser"));verify(mail,times(1)).send(owner.email,"new-device-login",Map.of());
        mvc.perform(request("POST","/devices/"+id+"/trust",admin,Map.of("days",30,"currentPassword",PASSWORD))).andExpect(status().isNotFound());
        mvc.perform(request("POST","/devices/"+id+"/trust",owner,Map.of("days",30,"currentPassword","wrong"))).andExpect(status().isUnauthorized());
        mvc.perform(request("POST","/devices/"+id+"/trust",owner,Map.of("days",30,"currentPassword",PASSWORD))).andExpect(status().isOk());
        mvc.perform(request("GET","/devices",owner,null)).andExpect(jsonPath("$.data[0].trusted").value(true));
        jdbc.update("update identity_devices set trust_expires_at=? where user_id=?",java.sql.Timestamp.from(Instant.now().minusSeconds(1)),owner.id);
        mvc.perform(request("GET","/devices",owner,null)).andExpect(jsonPath("$.data[0].trusted").value(false));
        when(sessions.list(owner.id,null)).thenReturn(List.of(new SessionView(family,id,"Browser","127.0.0.1",Instant.now(),Instant.now(),Instant.now().plusSeconds(600),true)));
        mvc.perform(request("DELETE","/devices/"+id+"/trust",owner,Map.of("currentPassword",PASSWORD))).andExpect(status().isOk());
        verify(sessions).revokeSession(owner.id,family);
    }
    @Test void authenticationHistorySurvivesLoginRollbackAndFiltersByTimeAndOutcome() throws Exception {
        mvc.perform(request("POST","/login",null,Map.of("email",owner.email,"password","wrong"))).andExpect(status().isUnauthorized());
        when(sessions.issue(any(AppUser.class))).thenReturn(new dev.kaidev.auth.dto.response.TokenResponse("access","refresh","Bearer",900));
        mvc.perform(request("POST","/login",null,Map.of("email",owner.email,"password",PASSWORD))).andExpect(status().isOk());
        history.record(admin.id,true,"SUCCESS");
        mvc.perform(request("GET","/login-history",owner,null)).andExpect(jsonPath("$.data.length()").value(2));
        mvc.perform(request("GET","/login-history",owner,null).param("successful","false")).andExpect(jsonPath("$.data.length()").value(1)).andExpect(jsonPath("$.data[0].reason").value("INVALID_CREDENTIALS"));
        mvc.perform(request("GET","/login-history",owner,null).param("from",Instant.now().plusSeconds(10).toString())).andExpect(status().isBadRequest());
    }
    @Test void tenantPolicyRequiresBothMembershipAndExplicitActionPermissions() throws Exception {
        var tenant=tenants.create(admin.id,"Engineering",PASSWORD);
        var identity=new dev.kaidev.common.security.IdentityCheck(admin.id,family,0L,0L);
        assertThat(tenants.profile(identity,owner.id,tenant.id(),"read")).isFalse();
        tenants.membership(admin.id,tenant.id(),owner.id,true,PASSWORD);
        assertThat(tenants.profile(identity,owner.id,tenant.id(),"read")).isTrue();
        assertThat(tenants.profile(identity,owner.id,UUID.randomUUID(),"read")).isFalse();
        assertThat(tenants.profile(identity,owner.id,null,"read")).isFalse();
        var regular=new dev.kaidev.common.security.IdentityCheck(owner.id,family,0L,0L);
        assertThat(tenants.profile(regular,admin.id,tenant.id(),"update")).isFalse();
        assertThat(tenants.profile(regular,owner.id,null,"update")).isTrue();
        tenants.membership(admin.id,tenant.id(),owner.id,false,PASSWORD);
        assertThat(tenants.profile(identity,owner.id,tenant.id(),"read")).isFalse();
        mvc.perform(request("GET","/tenants",admin,null)).andExpect(jsonPath("$.data[0].name").value("Engineering"));
        mvc.perform(post("/internal/identity/authorize-profile").header("X-Identity-Service-Key","identity-test-key-at-least-thirty-two-characters")
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(Map.of("identity",identity,"target",owner.id,"tenant",tenant.id(),"action","read"))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.allowed").value(false));
        mvc.perform(request("DELETE","/tenants/"+tenant.id(),admin,Map.of("currentPassword",PASSWORD))).andExpect(status().isOk());
    }
    @Test void exportIncludesOwnedDataButExcludesCredentialMaterialAndFailsClosedOnProfileOutage() throws Exception {
        when(profileData.export(owner.id)).thenReturn(json.readTree("{\"displayName\":\"Kai\"}"));
        String response=mvc.perform(request("POST","/export",owner,Map.of("currentPassword",PASSWORD))).andExpect(status().isOk())
                .andExpect(jsonPath("$.data.identity.id").value(owner.id.toString())).andExpect(jsonPath("$.data.profile.displayName").value("Kai"))
                .andReturn().getResponse().getContentAsString();
        assertThat(response).doesNotContain("passwordHash","tokenHash","secret_hash",PASSWORD);
        when(profileData.export(owner.id)).thenThrow(new dev.kaidev.common.exception.ApiException(dev.kaidev.common.api.code.CommonCode.SERVICE_UNAVAILABLE));
        mvc.perform(request("POST","/export",owner,Map.of("currentPassword",PASSWORD))).andExpect(status().isServiceUnavailable());
    }
    @Test void deletionRevokesImmediatelyRetriesDownstreamAndScrubsRelatedData() throws Exception {
        credentials.create(owner.id,"worker",Set.of("profile:read"),Instant.now().plusSeconds(300),PASSWORD);
        registry.observe(owner.id,new DeviceInfo(UUID.randomUUID(),"127.0.0.1","Browser"));
        history.record(owner.id,true,"SUCCESS");outbox.mail(owner.email,"password-changed",Map.of());
        String stale=jwt(owner),originalEmail=owner.email;
        mvc.perform(request("DELETE","/api/v1/users/me",owner,Map.of("currentPassword","wrong"))).andExpect(status().isUnauthorized());
        mvc.perform(request("DELETE","/api/v1/users/me",owner,Map.of("currentPassword",PASSWORD))).andExpect(status().isAccepted());
        mvc.perform(get(BASE+"/sessions").header("Authorization","Bearer "+stale)).andExpect(status().isUnauthorized());
        doThrow(new dev.kaidev.common.exception.ApiException(dev.kaidev.common.api.code.CommonCode.SERVICE_UNAVAILABLE)).when(profileData).delete(owner.id);
        assertThat(deletionWorker.processNext()).isTrue();
        assertThat(jdbc.queryForObject("select state from account_deletions where user_id=?",String.class,owner.id)).isEqualTo("PENDING");
        assertThat(users.findById(owner.id).orElseThrow().email).isEqualTo(originalEmail);
        doNothing().when(profileData).delete(owner.id);jdbc.update("update account_deletions set available_at=? where user_id=?",java.sql.Timestamp.from(Instant.now().minusSeconds(1)),owner.id);
        assertThat(deletionWorker.processNext()).isTrue();assertThat(deletionWorker.processNext()).isFalse();
        var scrubbed=users.findById(owner.id).orElseThrow();assertThat(scrubbed.email).doesNotContain(originalEmail);assertThat(scrubbed.passwordHash).isEqualTo("!deleted");
        for(String table:List.of("identity_api_keys","identity_devices","authentication_history"))assertThat(jdbc.queryForObject("select count(*) from "+table+" where user_id=?",Integer.class,owner.id)).isZero();
        assertThat(jdbc.queryForObject("select encrypted_payload from auth_outbox",String.class)).isEmpty();
        assertThat(jdbc.queryForObject("select state from account_deletions where user_id=?",String.class,owner.id)).isEqualTo("COMPLETED");
    }
    @Test void deletingLastManagerIsRejectedWithoutPartialChanges() throws Exception {
        mvc.perform(request("DELETE","/api/v1/users/me",admin,Map.of("currentPassword",PASSWORD))).andExpect(status().isConflict());
        assertThat(users.findById(admin.id).orElseThrow().active).isTrue();
        assertThat(jdbc.queryForObject("select count(*) from account_deletions",Integer.class)).isZero();
    }

    private String reauthenticate(AppUser actor) throws Exception {
        return json.readTree(mvc.perform(request("POST","/reauthenticate",actor,Map.of("currentPassword",PASSWORD)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("data").path("reauthenticationToken").asText();
    }
    @Test void searchSupportsWhitelistedSortAndExplicitStatusFilters() throws Exception {
        mvc.perform(request("GET","/users",admin,null).param("sort","email,desc"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data[0].id").value(owner.id.toString()));
        mvc.perform(request("GET","/users",admin,null).param("sort","email,asc").param("size","1").param("page","1"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data[0].id").value(owner.id.toString()));
        for(String sort:List.of("passwordHash,desc","email,invalid","email,asc,id,desc"))
            mvc.perform(request("GET","/users",admin,null).param("sort",sort)).andExpect(status().isBadRequest());
        mvc.perform(request("PATCH","/users/"+owner.id+"/status",admin,Map.of("status","DISABLED","currentPassword",PASSWORD)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.status").value("DISABLED"));
        mvc.perform(request("GET","/users",admin,null).param("status","DISABLED")).andExpect(jsonPath("$.data.length()").value(1));
        mvc.perform(request("GET","/users",admin,null).param("status","SUSPENDED")).andExpect(jsonPath("$.data.length()").value(0));
        mvc.perform(request("GET","/users",admin,null).param("status","DISABLED").param("active","true")).andExpect(status().isBadRequest());
        mvc.perform(request("PATCH","/users/"+owner.id+"/status",admin,Map.of("status","ENABLED"))).andExpect(status().isBadRequest());
    }
    @Test void currentSessionReturnsOnlyTheAuthenticatedSidAndOwnedMetadata() throws Exception {
        var own=new SessionView(family,UUID.randomUUID(),"Browser","127.0.0.1",Instant.now(),Instant.now(),Instant.now().plusSeconds(600),true);
        var other=new SessionView(UUID.randomUUID(),UUID.randomUUID(),"Another browser","127.0.0.2",Instant.now(),Instant.now(),Instant.now().plusSeconds(600),false);
        when(sessions.list(owner.id,family)).thenReturn(List.of(other,own));
        mvc.perform(request("GET","/session/current",owner,null).param("userId",admin.id.toString()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.id").value(family.toString())).andExpect(jsonPath("$.data.current").value(true));
        verify(sessions).list(owner.id,family);
        when(sessions.list(owner.id,family)).thenReturn(List.of(other));
        mvc.perform(request("GET","/session/current",owner,null)).andExpect(status().isNotFound());
    }
    @Test void exportRequiresPasswordVerifiedProofBoundToOwnerSessionAndExpiry() throws Exception {
        when(profileData.export(owner.id)).thenReturn(json.readTree("{\"displayName\":\"Kai\"}"));
        mvc.perform(request("POST","/reauthenticate",owner,Map.of("currentPassword","wrong"))).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/users/me/export").header("Authorization","Bearer "+jwt(owner))).andExpect(status().isUnauthorized());
        String proof=reauthenticate(owner);
        assertThat(jdbc.queryForObject("select proof_hash from reauthentication_proofs",String.class)).doesNotContain(proof);
        mvc.perform(get("/api/v1/users/me/export").header("Authorization","Bearer "+jwt(owner)).header("X-Reauthentication-Token",proof))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.profile.displayName").value("Kai"))
                .andExpect(com.atlassian.oai.validator.mockmvc.SwaggerValidatorMatchers.swagger().isValid("../docs/openapi.json"));
        mvc.perform(get("/api/v1/users/me/export").header("Authorization","Bearer "+jwt(admin)).header("X-Reauthentication-Token",proof)).andExpect(status().isUnauthorized());
        UUID original=family;family=UUID.randomUUID();
        mvc.perform(get("/api/v1/users/me/export").header("Authorization","Bearer "+jwt(owner)).header("X-Reauthentication-Token",proof)).andExpect(status().isUnauthorized());
        family=original;
        jdbc.update("update reauthentication_proofs set expires_at=?",java.sql.Timestamp.from(Instant.now().minusSeconds(1)));
        mvc.perform(get("/api/v1/users/me/export").header("Authorization","Bearer "+jwt(owner)).header("X-Reauthentication-Token",proof)).andExpect(status().isUnauthorized());
        mvc.perform(delete("/api/v1/users/me").header("Authorization","Bearer "+jwt(owner)).header("X-Reauthentication-Token",proof)
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }
}
