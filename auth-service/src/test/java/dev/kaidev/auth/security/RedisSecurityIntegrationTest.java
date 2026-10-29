package dev.kaidev.auth.security;

import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.service.SessionService;
import dev.kaidev.common.exception.ApiException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jwt.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Uses a disposable real Redis; never touches Compose data or flushes a shared database. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RedisSecurityIntegrationTest {
    private String container;
    private LettuceConnectionFactory factory;
    private StringRedisTemplate redis;
    private SecurityState state;
    private SessionService first, second;
    private UserRepository users;
    private AppUser user;
    private final JwtEncoder encoder = parameters -> Jwt.withTokenValue("test-access")
            .header("alg", "RS256").claims(c -> c.putAll(parameters.getClaims().getClaims())).build();

    private static String docker(String... args) throws Exception {
        var command = new ArrayList<String>(); command.add("docker"); command.addAll(List.of(args));
        var process = new ProcessBuilder(command).redirectErrorStream(true).start();
        if (!process.waitFor(60, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new IllegalStateException("Docker timed out"); }
        String output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
        if (process.exitValue() != 0) throw new IllegalStateException("Docker is required for Redis security integration tests: " + output);
        return output;
    }

    @BeforeAll void startRedis() throws Exception {
        container = docker("run", "--rm", "-d", "-p", "127.0.0.1::6379", "redis:7.4-alpine");
        int port = Integer.parseInt(docker("port", container, "6379/tcp").split(":")[1]);
        factory = new LettuceConnectionFactory("127.0.0.1", port); factory.afterPropertiesSet();
        redis = new StringRedisTemplate(factory); redis.afterPropertiesSet();
        for (int i = 0; i < 100; i++) {
            try (var connection = factory.getConnection()) { if ("PONG".equals(connection.ping())) return; }
            catch (Exception ignored) { Thread.sleep(50); }
        }
        throw new IllegalStateException("Isolated Redis did not start");
    }
    @AfterAll void stopRedis() throws Exception {
        if (factory != null) factory.destroy();
        if (container != null) docker("rm", "-f", container);
    }
    @BeforeEach void setup() {
        state = new SecurityState(redis, "security:{test-" + UUID.randomUUID() + "}:");
        first = new SessionService(state, encoder, "http://issuer.test", 60);
        second = new SessionService(state, encoder, "http://issuer.test", 60);
        users = mock(UserRepository.class);
        user = new AppUser("test@example.com", "hash"); user.emailVerified = true;
        when(users.findByIdForUpdate(user.id)).thenReturn(Optional.of(user));
    }

    @Test void parallelRotationAcrossInstancesHasOneWinnerAndReuseRevokesWinner() throws Exception {
        String original = first.issue(user).refreshToken();
        var start = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(12)) {
            List<Future<String>> requests = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                SessionService instance = i % 2 == 0 ? first : second;
                requests.add(pool.submit(() -> {
                    start.await();
                    try { return instance.rotate(original, users).refreshToken(); }
                    catch (ApiException e) { assertThat(e.apiCode().name()).isEqualTo("INVALID_REFRESH_TOKEN"); return null; }
                }));
            }
            start.countDown();
            List<String> winners = new ArrayList<>();
            for (var request : requests) { String value = request.get(10, TimeUnit.SECONDS); if (value != null) winners.add(value); }
            assertThat(winners).hasSize(1);
            assertInvalid(() -> first.rotate(winners.getFirst(), users));
        }
    }

    @Test void sequentialReplayRevokesOnlyTheCompromisedFamily() {
        String original = first.issue(user).refreshToken();
        String otherDevice = first.issue(user).refreshToken();
        String next = second.rotate(original, users).refreshToken();
        assertInvalid(() -> first.rotate(original, users));
        assertInvalid(() -> second.rotate(next, users));
        assertThat(first.rotate(otherDevice, users).refreshToken()).isNotBlank();
    }

    @Test void logoutWithConsumedTokenRevokesItsCurrentDescendant() {
        String original = first.issue(user).refreshToken();
        String next = first.rotate(original, users).refreshToken();
        second.revoke(original);
        assertInvalid(() -> first.rotate(next, users));
        second.revoke(original); // Idempotent.
    }

    @Test void logoutAllInvalidatesEveryDeviceButAllowsAFreshLogin() {
        String one = first.issue(user).refreshToken(), two = second.issue(user).refreshToken();
        second.revokeAll(user.id);
        assertInvalid(() -> first.rotate(one, users));
        assertInvalid(() -> second.rotate(two, users));
        String fresh = first.issue(user).refreshToken();
        assertThat(second.rotate(fresh, users).refreshToken()).isNotBlank();
    }

    @Test void logoutAllCannotBeUndoneByAnInflightRotation() throws Exception {
        for (int i = 0; i < 10; i++) {
            String token = first.issue(user).refreshToken();
            var start = new CountDownLatch(1);
            try (var pool = Executors.newFixedThreadPool(2)) {
                var rotating = pool.submit(() -> { start.await(); try { return first.rotate(token, users).refreshToken(); }
                    catch (ApiException e) { return null; } });
                var logout = pool.submit(() -> { start.await(); second.revokeAll(user.id); return true; });
                start.countDown(); logout.get(10, TimeUnit.SECONDS);
                String next = rotating.get(10, TimeUnit.SECONDS);
                if (next != null) assertInvalid(() -> first.rotate(next, users));
            }
        }
    }

    @Test void expiredFamiliesCannotBeResurrected() throws Exception {
        var shortLived = new SessionService(state, encoder, "http://issuer.test", 1);
        String token = shortLived.issue(user).refreshToken();
        Thread.sleep(1100);
        assertInvalid(() -> second.rotate(token, users));
    }

    @Test void signingFailureDoesNotConsumeRefreshToken() {
        String token = first.issue(user).refreshToken();
        var broken = new SessionService(state, parameters -> { throw new JwtEncodingException("test failure"); }, "http://issuer.test", 60);
        assertThatThrownBy(() -> broken.rotate(token, users)).isInstanceOf(JwtEncodingException.class);
        assertThat(second.rotate(token, users).refreshToken()).isNotBlank();
    }

    @Test void rateLimitIsAtomicAcrossInstancesAndRecoversAfterExpiry() throws Exception {
        var a = new AbuseProtection(state, 3, 10, 1, 3, 60, 1);
        var b = new AbuseProtection(state, 3, 10, 1, 3, 60, 1);
        try (var pool = Executors.newFixedThreadPool(12)) {
            List<Callable<Long>> requests = new ArrayList<>();
            for (int i = 0; i < 12; i++) { var instance = i % 2 == 0 ? a : b; requests.add(() -> instance.rateLimit("127.0.0.1", true)); }
            long accepted = 0;
            for (var result : pool.invokeAll(requests)) if (result.get() == 0) accepted++;
            assertThat(accepted).isEqualTo(3);
        }
        assertThat(a.rateLimit("127.0.0.2", true)).isZero();
        Thread.sleep(1100);
        assertThat(b.rateLimit("127.0.0.1", true)).isZero();
    }

    @Test void temporaryLockDoesNotExtendOnFailureAndSuccessCannotBypassIt() throws Exception {
        var protection = new AbuseProtection(state, 20, 60, 60, 3, 60, 1);
        assertThat(protection.failed(user.email)).isZero();
        assertThat(protection.failed(user.email)).isZero();
        assertThat(protection.failed(user.email)).isPositive();
        Thread.sleep(300);
        long remaining = protection.failed(user.email);
        assertThat(remaining).isBetween(1L, 850L);
        assertThat(protection.succeeded(user.email)).isPositive();
        Thread.sleep(800);
        assertThat(protection.lockedFor(user.email)).isZero();
        assertThat(protection.failed(user.email)).isZero();
        assertThat(protection.succeeded(user.email)).isZero();
        assertThat(protection.failed(user.email)).isZero();
    }

    @Test void rotationRetainsTombstonesAndAbsoluteExpiryInsteadOfExtendingSessions() throws Exception {
        String original = first.issue(user).refreshToken();
        Thread.sleep(40);
        String next = first.rotate(original, users).refreshToken();
        String oldKey = state.key("token:" + dev.kaidev.common.security.ClientIdentity.hash(original));
        String newKey = state.key("token:" + dev.kaidev.common.security.ClientIdentity.hash(next));
        assertThat(redis.hasKey(oldKey)).isTrue();
        assertThat(redis.getExpire(newKey, TimeUnit.MILLISECONDS)).isLessThanOrEqualTo(redis.getExpire(oldKey, TimeUnit.MILLISECONDS) + 100);
        String keys = String.join(" ", redis.keys(state.key("*")));
        assertThat(keys).doesNotContain(original, next, user.email);
    }

    @Test void listAndRevokeSessionEnforceOwnershipAndInvalidateAccessStateImmediately() {
        String one = first.issue(user).refreshToken(), two = first.issue(user).refreshToken();
        var listed = first.list(user.id, null); assertThat(listed).hasSize(2);
        var target = listed.getFirst();
        assertThat(first.active(user.id, target.id(), 0)).isTrue();
        assertThat(first.active(UUID.randomUUID(), target.id(), 0)).isFalse();
        assertThatThrownBy(() -> first.revokeSession(UUID.randomUUID(), target.id())).isInstanceOf(ApiException.class);
        assertThat(first.active(user.id, target.id(), 0)).isTrue();
        second.revokeSession(user.id, target.id());
        assertThat(first.active(user.id, target.id(), 0)).isFalse();
        assertThat(first.list(user.id, null)).hasSize(1);
        int rejected = 0;
        for (String token : List.of(one, two)) {
            try { first.rotate(token, users); } catch (ApiException e) { rejected++; }
        }
        assertThat(rejected).isEqualTo(1);
        first.revokeAll(user.id); assertThat(first.list(user.id, null)).isEmpty();
    }

    @Test void credentialRevisionPreventsOldRefreshFromReceivingNewRoles() {
        String old = first.issue(user).refreshToken(); user.credentialRevision++;
        assertInvalid(() -> second.rotate(old, users));
    }

    @Test void deactivatedUserCannotIssueOrRefresh() {
        String old = first.issue(user).refreshToken(); user.active = false;
        assertInvalid(() -> second.rotate(old, users));
        assertThatThrownBy(() -> first.issue(user)).isInstanceOfSatisfying(ApiException.class,
                e -> assertThat(e.apiCode().name()).isEqualTo("ACCOUNT_DISABLED"));
    }

    private static void assertInvalid(org.assertj.core.api.ThrowableAssert.ThrowingCallable callable) {
        assertThatThrownBy(callable).isInstanceOfSatisfying(ApiException.class,
                e -> assertThat(e.apiCode().name()).isEqualTo("INVALID_REFRESH_TOKEN"));
    }
}
