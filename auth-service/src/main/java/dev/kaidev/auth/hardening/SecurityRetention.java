package dev.kaidev.auth.hardening;
import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
/** Proof material is erased on expiry, including jobs that exhausted their retry budget. */
@Component
public class SecurityRetention {
    private final JdbcTemplate jdbc;
    public SecurityRetention(JdbcTemplate jdbc){this.jdbc=jdbc;}
    @Scheduled(fixedDelayString="${app.outbox.cleanup-ms:3600000}") @Transactional
    public void cleanup(){
        var now=Instant.now();
        jdbc.update("update auth_outbox set encrypted_payload='',state='EXPIRED',completed_at=? where expires_at<? and state in ('PENDING','FAILED')",Timestamp.from(now),Timestamp.from(now));
        jdbc.update("delete from auth_outbox where completed_at<?",Timestamp.from(now.minusSeconds(30L*86400)));
        jdbc.update("delete from authentication_history where occurred_at<?",Timestamp.from(now.minusSeconds(30L*86400)));
        jdbc.update("delete from reauthentication_proofs where expires_at<=CURRENT_TIMESTAMP");
        // Keep consumed refresh hashes for the entire family lifetime for replay detection.
        jdbc.update("delete from identity_sessions where expires_at<?",Timestamp.from(now.minusSeconds(86400)));
    }
}
