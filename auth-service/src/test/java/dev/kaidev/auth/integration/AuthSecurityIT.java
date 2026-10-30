package dev.kaidev.auth.integration;

import com.fasterxml.jackson.databind.*;
import dev.kaidev.auth.client.MailServiceClient;
import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.security.JwtKeyRing;
import java.nio.file.*;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
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
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.*;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Real Flyway/PostgreSQL transactions, Redis Lua, JWT decoder and HTTP security chain. */
@Testcontainers
@SpringBootTest(properties = {"app.observability.session-poll-ms=3600000", "app.jwt.key-set=", "app.security.login-ip-limit=200",
        "app.security.auth-ip-limit=1000", "spring.flyway.locations=classpath:db/migration"})
@AutoConfigureMockMvc
class AuthSecurityIT {
    @Container static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17-alpine");
    @Container static final GenericContainer<?> REDIS = new GenericContainer<>("redis:7.4-alpine").withExposedPorts(6379);
    static Path directory;
    @DynamicPropertySource static void properties(DynamicPropertyRegistry p) throws Exception {
        p.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        p.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        p.add("spring.datasource.username", POSTGRES::getUsername);
        p.add("spring.datasource.password", POSTGRES::getPassword);
        p.add("spring.flyway.user", POSTGRES::getUsername);
        p.add("spring.flyway.password", POSTGRES::getPassword);
        p.add("spring.data.redis.host", REDIS::getHost);
        p.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        directory = Files.createTempDirectory("p4-keys-");
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); var pair = generator.generateKeyPair();
        Path priv = directory.resolve("private.pem"), pub = directory.resolve("public.pem");
        Files.writeString(priv, "-----BEGIN PRIVATE KEY-----\n" + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----");
        Files.writeString(pub, "-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----");
        p.add("app.private-key", priv::toString); p.add("app.public-key", pub::toString);
    }
    @AfterAll static void removeKeys() throws Exception {
        if (directory != null) { Files.deleteIfExists(directory.resolve("private.pem")); Files.deleteIfExists(directory.resolve("public.pem")); Files.deleteIfExists(directory); }
    }
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwords;
    @Autowired JwtKeyRing keys;
    @Autowired org.springframework.boot.actuate.health.HealthEndpointGroups healthGroups;
    @Autowired org.springframework.jdbc.core.JdbcTemplate resilienceJdbc;

    @Test void readinessIncludesDependenciesAndPostgresEnforcesDeadlines() {
        var readiness = healthGroups.get("readiness");
        assertThat(readiness.isMember("db")).isTrue();
        assertThat(readiness.isMember("redis")).isTrue();
        assertThat(healthGroups.get("liveness").isMember("db")).isFalse();
        assertThat(resilienceJdbc.queryForObject("show statement_timeout", String.class)).isEqualTo("5s");
        assertThat(resilienceJdbc.queryForObject("show lock_timeout", String.class)).isEqualTo("2s");
    }
    @MockitoBean MailServiceClient mail;
    AppUser owner, other;
    static final String BASE = "/api/v1/auth", PASSWORD = "StrongPassword123!";
    @BeforeEach void accounts() {
        owner = account(); other = account();
    }
    private AppUser account() {
        var user = new AppUser(UUID.randomUUID()+"@example.com", passwords.encode(PASSWORD));
        user.emailVerified = true; return users.saveAndFlush(user);
    }
    private JsonNode login(AppUser user) throws Exception {
        return json.readTree(mvc.perform(post(BASE+"/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("email",user.email,"password",PASSWORD))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("data");
    }
    private JsonNode refresh(String token, int status) throws Exception {
        return json.readTree(mvc.perform(post(BASE+"/refresh").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("refreshToken", token))))
                .andExpect(status().is(status)).andReturn().getResponse().getContentAsString()).path("data");
    }
    private void access(JsonNode tokens, int status) throws Exception {
        mvc.perform(get(BASE+"/sessions").header("Authorization", "Bearer "+tokens.path("accessToken").asText()))
                .andExpect(status().is(status));
    }
    @Test void concurrentRefreshHasOneWinnerAndReplayRevokesAccessAndDescendant() throws Exception {
        JsonNode initial = login(owner), independent = login(owner);
        var start = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(2)) {
            List<Future<JsonNode>> requests = new ArrayList<>();
            for (int i=0;i<2;i++) requests.add(pool.submit(() -> {
                start.await();
                var result = mvc.perform(post(BASE+"/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("refreshToken",initial.path("refreshToken").asText())))).andReturn().getResponse();
                assertThat(result.getStatus()).isIn(200,401);
                return result.getStatus()==200 ? json.readTree(result.getContentAsString()).path("data") : null;
            }));
            start.countDown(); var winners = new ArrayList<JsonNode>();
            for (var request:requests) { var value=request.get(20,TimeUnit.SECONDS); if(value!=null) winners.add(value); }
            assertThat(winners).hasSize(1);
            refresh(winners.getFirst().path("refreshToken").asText(),401);
            access(initial,401); access(winners.getFirst(),401); access(independent,200);
        }
    }
    @Test void sequentialReplayCommitsRevocationDespiteUnauthorizedResponse() throws Exception {
        var initial=login(owner); var next=refresh(initial.path("refreshToken").asText(),200);
        refresh(initial.path("refreshToken").asText(),401);
        refresh(next.path("refreshToken").asText(),401); access(next,401);
    }
    @Test void logoutAllRejectsBothAccessAndRefreshForEveryDeviceAndPreservesOtherUsers() throws Exception {
        var one=login(owner); var two=login(owner); var stranger=login(other);
        mvc.perform(post(BASE+"/logout-all").header("Authorization","Bearer "+one.path("accessToken").asText()))
                .andExpect(status().isOk());
        for(var device:List.of(one,two)) { access(device,401); refresh(device.path("refreshToken").asText(),401); }
        access(stranger,200); access(login(owner),200);
    }
    @Test void anotherUserCannotRevokeAnOwnedSession() throws Exception {
        var victim=login(owner); var attacker=login(other);
        var sessions=json.readTree(mvc.perform(get(BASE+"/sessions").header("Authorization","Bearer "+victim.path("accessToken").asText()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("data");
        mvc.perform(delete(BASE+"/sessions/"+sessions.get(0).path("id").asText())
                .header("Authorization","Bearer "+attacker.path("accessToken").asText()))
                .andExpect(status().isNotFound());
        access(victim,200); refresh(victim.path("refreshToken").asText(),200);
    }
    @Test void bruteForceLocksAccountAndCorrectPasswordCannotBypassLock() throws Exception {
        for(int i=0;i<5;i++) mvc.perform(post(BASE+"/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("email",owner.email,"password","WrongPassword123!"))))
                .andExpect(status().is(i<4 ? 401 : 429));
        mvc.perform(post(BASE+"/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("email",owner.email,"password",PASSWORD))))
                .andExpect(status().isTooManyRequests()).andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.code").value("ACCOUNT_TEMPORARILY_LOCKED"));
    }
    @Test void rejectsExpiredAndForgedJwtBeforeIdentityLookup() throws Exception {
        var claims=JwtClaimsSet.builder().issuer("http://localhost:8701").subject(owner.id.toString())
                .audience(List.of("hybrid-api")).issuedAt(Instant.now().minusSeconds(600)).expiresAt(Instant.now().minusSeconds(120))
                .claim("sid",UUID.randomUUID().toString()).claim("cv",0L).claim("sv",0L).build();
        String expired=keys.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        String valid=login(owner).path("accessToken").asText(); String[] parts=valid.split("\\.");
        String forged=parts[0]+"."+Base64.getUrlEncoder().withoutPadding().encodeToString(
                new String(Base64.getUrlDecoder().decode(parts[1]),java.nio.charset.StandardCharsets.UTF_8)
                        .replace(owner.id.toString(),other.id.toString()).getBytes(java.nio.charset.StandardCharsets.UTF_8))+"."+parts[2];
        for(String token:List.of(expired,forged)) mvc.perform(get(BASE+"/sessions").header("Authorization","Bearer "+token))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }
    @Test void refreshIntrospectionTracksRotationAndMachineKeysFollowLogoutGeneration() throws Exception {
        var initial=login(owner);var observer=login(owner);
        String caller=observer.path("accessToken").asText();String refresh=initial.path("refreshToken").asText();
        mvc.perform(post(BASE+"/introspect").header("Authorization","Bearer "+caller).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("token",refresh))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.active").value(true));
        refresh(refresh,200);
        mvc.perform(post(BASE+"/introspect").header("Authorization","Bearer "+caller).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("token",refresh))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.active").value(false));
        var created=json.readTree(mvc.perform(post(BASE+"/api-keys").header("Authorization","Bearer "+caller).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("name","integration-worker","scopes",Set.of("profile:read"),"expiresAt",Instant.now().plusSeconds(3600).toString(),"currentPassword",PASSWORD))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("data");
        String secret=created.path("secret").asText();
        mvc.perform(post(BASE+"/service-tokens").header("X-Api-Key",secret)).andExpect(status().isOk());
        mvc.perform(post(BASE+"/logout-all").header("Authorization","Bearer "+caller)).andExpect(status().isOk());
        mvc.perform(post(BASE+"/service-tokens").header("X-Api-Key",secret)).andExpect(status().isUnauthorized());
    }
    @Autowired dev.kaidev.auth.hardening.SessionMetrics sessionMetrics;
    @Autowired io.micrometer.core.instrument.MeterRegistry meters;
    @Test void activeSessionGaugeUsesSqlAndReflectsRevocation(){
        sessionMetrics.refresh();double before=meters.get("auth.active.sessions").gauge().value();
        try{
            var one=login(owner);sessionMetrics.refresh();
            assertThat(meters.get("auth.active.sessions").gauge().value()).isEqualTo(before+1);
            mvc.perform(post(BASE+"/logout-all").header("Authorization","Bearer "+one.path("accessToken").asText())).andExpect(status().isOk());
            sessionMetrics.refresh();assertThat(meters.get("auth.active.sessions").gauge().value()).isEqualTo(before);
        }catch(Exception e){throw new RuntimeException(e);}
    }
}
