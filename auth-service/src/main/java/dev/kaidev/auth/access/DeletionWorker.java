package dev.kaidev.auth.access;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;

/** Durable retry without an expiry: failed downstream erasure must remain visible and retryable. */
@Component
public class DeletionWorker {
    private volatile boolean stopping;
    @org.springframework.context.event.EventListener(org.springframework.context.event.ContextClosedEvent.class)
    public void stopClaiming() { stopping = true; }
    private final JdbcTemplate jdbc;private final AccountData accounts;private final TransactionTemplate tx;private final boolean enabled;
    public DeletionWorker(JdbcTemplate jdbc,AccountData accounts,PlatformTransactionManager manager,@Value("${app.outbox.worker-enabled:true}")boolean enabled){
        this.jdbc=jdbc;this.accounts=accounts;this.tx=new TransactionTemplate(manager);this.enabled=enabled;
    }
    @Scheduled(fixedDelayString="${app.deletion.poll-ms:10000}") public void tick(){if(enabled)processNext();}
    public boolean processNext(){
        if(stopping)return false;
        record Claim(UUID owner,int attempts){}
        Claim claim=tx.execute(status->{
            var ready=jdbc.query("select user_id,attempts from account_deletions where state in ('PENDING','PROCESSING') and available_at<=CURRENT_TIMESTAMP order by requested_at limit 1 for update skip locked",(r,n)->new Claim(r.getObject(1,UUID.class),r.getInt(2)+1));
            if(ready.isEmpty())return null;var item=ready.getFirst();var id=item.owner();
            jdbc.update("update account_deletions set state='PROCESSING',attempts=attempts+1,available_at=? where user_id=?",Timestamp.from(Instant.now().plusSeconds(120)),id);return item;
        });
        if(claim==null)return false;var owner=claim.owner();
        try{accounts.finishDeletion(owner);}catch(RuntimeException e){
            dev.kaidev.common.security.SecurityAudit.record(dev.kaidev.common.security.SecurityAudit.Event.ACCOUNT_DELETION_FAILURE,
                    dev.kaidev.common.security.SecurityAudit.Outcome.UNAVAILABLE,owner.toString(),null);
            jdbc.update("update account_deletions set state='PENDING',available_at=? where user_id=? and state='PROCESSING' and attempts=?",Timestamp.from(Instant.now().plusSeconds(dev.kaidev.common.resilience.DependencyGuard.backoffSeconds(claim.attempts()))),owner,claim.attempts());
        }
        return true;
    }
}
