package dev.kaidev.auth.hardening;

import dev.kaidev.auth.entity.AppUser;
import dev.kaidev.auth.repository.UserRepository;
import dev.kaidev.auth.identity.DeviceInfo;
import dev.kaidev.auth.outbox.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.*;
import org.springframework.transaction.support.TransactionTemplate;
import static org.assertj.core.api.Assertions.*;

@DataJpaTest(properties={"app.outbox.encryption-key=1212121212121212121212121212121212121212121212121212121212121212"})
@Import({SessionLedger.class,AuthAuditStore.class,AuthOutbox.class,OutboxCrypto.class,DurableSecurityTest.JsonConfig.class})
@Transactional(propagation=Propagation.NOT_SUPPORTED)
class DurableSecurityTest {
    @org.springframework.boot.test.context.TestConfiguration static class JsonConfig { @Bean ObjectMapper json(){return new ObjectMapper();} }
    @Autowired UserRepository users;
    @Autowired SessionLedger ledger;
    @Autowired AuthOutbox outbox;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager manager;
    AppUser user;UUID sid;DeviceInfo device;
    void tx(Runnable work){new TransactionTemplate(manager).executeWithoutResult(s->work.run());}
    @BeforeEach void setup(){user=new AppUser(UUID.randomUUID()+"@example.com","hash");user.emailVerified=true;user=users.saveAndFlush(user);sid=UUID.randomUUID();device=new DeviceInfo(UUID.randomUUID(),"127.0.0.1","Browser");}
    @AfterEach void cleanup(){users.deleteById(user.id);jdbc.update("delete from auth_outbox");}
    @Test void revokedSessionCannotBecomeValidAfterServiceReconstruction(){
        tx(()->ledger.create(user,sid,"a".repeat(64),device,900));
        assertThat(ledger.active(user.id,sid,0,0)).isTrue();ledger.revoke(user.id,sid);
        assertThat(ledger.active(user.id,sid,0,0)).isFalse();
        assertThat(jdbc.queryForObject("select count(*) from security_audit_records where target=? and event='SESSION_REVOKED'",Integer.class,user.id)).isEqualTo(1);
        ledger.revokeAll(user.id);assertThat(users.findById(user.id).orElseThrow().sessionGeneration).isEqualTo(1);
        tx(()->{var fresh=users.findById(user.id).orElseThrow();ledger.create(fresh,UUID.randomUUID(),"b".repeat(64),device,900);});
        assertThat(ledger.active(user.id,sid,0,0)).isFalse();
    }
    @Test void activityUpdateNeverClearsRevocation(){
        tx(()->ledger.create(user,sid,"c".repeat(64),device,900));
        jdbc.update("update identity_sessions set last_activity_at=? where id=?",java.sql.Timestamp.from(Instant.now().minusSeconds(60)),sid);
        assertThat(ledger.active(user.id,sid,0,0)).isTrue();
        assertThat(jdbc.queryForObject("select last_activity_at from identity_sessions where id=?",java.sql.Timestamp.class,sid).toInstant()).isAfter(Instant.now().minusSeconds(10));
        ledger.revoke(user.id,sid);assertThat(ledger.active(user.id,sid,0,0)).isFalse();
        assertThat(jdbc.queryForObject("select revoked_at from identity_sessions where id=?",java.sql.Timestamp.class,sid)).isNotNull();
    }
    @Test void consumedRefreshReplayDurablyRevokesFamily(){
        tx(()->ledger.create(user,sid,"a".repeat(64),device,900));
        tx(()->ledger.consume("a".repeat(64),"b".repeat(64),device));
        tx(()->assertThat(ledger.inspect(users.findById(user.id).orElseThrow(),"a".repeat(64))).isEqualTo(SessionLedger.Rotation.USED));
        assertThat(ledger.active(user.id,sid,0,0)).isFalse();
        assertThat(ledger.inspect(user,"b".repeat(64))).isEqualTo(SessionLedger.Rotation.INACTIVE);
    }
    @Test void redisAheadOfSqlStillCommitsFamilyRevocation() throws Exception {
        String raw="opaque-refresh",hash=dev.kaidev.common.security.ClientIdentity.hash(raw);
        tx(()->ledger.create(user,sid,hash,device,900));
        var state=org.mockito.Mockito.mock(dev.kaidev.auth.security.SecurityState.class);
        org.mockito.Mockito.when(state.key(org.mockito.ArgumentMatchers.anyString())).thenAnswer(i->i.getArgument(0));
        org.mockito.Mockito.when(state.get("token:"+hash)).thenReturn(user.id+"|"+sid+"|0");
        var details=new dev.kaidev.auth.identity.SessionMetadata(user.id.toString(),0,0,device.deviceId(),"Browser","127.0.0.1",0,0,Long.MAX_VALUE);
        org.mockito.Mockito.when(state.get("session:"+sid)).thenReturn(new ObjectMapper().writeValueAsString(details));
        org.mockito.Mockito.when(state.execute(org.mockito.ArgumentMatchers.any(),org.mockito.ArgumentMatchers.anyList(),org.mockito.ArgumentMatchers.any(String[].class))).thenReturn(-1L);
        var encoder=org.mockito.Mockito.mock(org.springframework.security.oauth2.jwt.JwtEncoder.class);
        org.mockito.Mockito.when(encoder.encode(org.mockito.ArgumentMatchers.any())).thenReturn(org.springframework.security.oauth2.jwt.Jwt.withTokenValue("signed").header("alg","RS256").subject(user.id.toString()).build());
        var service=new dev.kaidev.auth.service.SessionService(state,encoder,"http://issuer",900,null,"",ledger);
        // The service proxy uses noRollbackFor; catching the same marker here models that commit boundary.
        tx(()->assertThatThrownBy(()->service.rotate(raw,users)).isInstanceOf(RefreshReuseException.class));
        assertThat(ledger.active(user.id,sid,0,0)).isFalse();
    }
    @Test void encryptedJobSurvivesWorkerLeaseAndRetryWithoutPlaintextAtRest(){
        UUID id=outbox.mail("private@example.com","password-reset",Map.of("resetToken","secret-proof"));
        String encrypted=jdbc.queryForObject("select encrypted_payload from auth_outbox where id=?",String.class,id);
        assertThat(encrypted).doesNotContain("private@example.com","secret-proof","resetToken");
        var job=outbox.claim();assertThat(job.id()).isEqualTo(id);assertThat(outbox.claim()).isNull();
        assertThat(outbox.payload(job).path("variables").path("resetToken").asText()).isEqualTo("secret-proof");
        outbox.retry(job);assertThat(outbox.claim()).isNull();
        jdbc.update("update auth_outbox set available_at=? where id=?",java.sql.Timestamp.from(Instant.now().minusSeconds(1)),id);
        var next=outbox.claim();assertThat(next.attempts()).isEqualTo(1);
        // Simulate a crashed worker: lease expiry allows another worker to claim it.
        jdbc.update("update auth_outbox set available_at=? where id=?",java.sql.Timestamp.from(Instant.now().minusSeconds(1)),id);
        var replacement=outbox.claim();outbox.complete(next,"SENT");
        assertThat(jdbc.queryForObject("select state from auth_outbox where id=?",String.class,id)).isEqualTo("PROCESSING");
        outbox.complete(replacement,"SENT");
        assertThat(jdbc.queryForObject("select encrypted_payload from auth_outbox where id=?",String.class,id)).isEmpty();
    }
    @Test void rolledBackAccountTransactionCannotLeaveAnEmailJob(){
        var template=new TransactionTemplate(manager);
        template.executeWithoutResult(s->{outbox.mail("private@example.com","password-changed",Map.of());s.setRollbackOnly();});
        assertThat(jdbc.queryForObject("select count(*) from auth_outbox",Integer.class)).isZero();
    }
}
