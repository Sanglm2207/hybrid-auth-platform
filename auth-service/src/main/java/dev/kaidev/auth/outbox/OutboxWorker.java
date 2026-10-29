package dev.kaidev.auth.outbox;

import dev.kaidev.auth.client.MailServiceClient;
import dev.kaidev.auth.service.AccountLifecycleService;
import dev.kaidev.common.security.SecurityAudit;
import java.time.Instant;
import java.util.*;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class OutboxWorker {
    private final AuthOutbox outbox;private final AccountLifecycleService accounts;private final MailServiceClient mail;private final boolean enabled;
    public OutboxWorker(AuthOutbox outbox,AccountLifecycleService accounts,MailServiceClient mail,@Value("${app.outbox.worker-enabled:true}") boolean enabled){this.outbox=outbox;this.accounts=accounts;this.mail=mail;this.enabled=enabled;}
    @Scheduled(fixedDelayString="${app.outbox.poll-ms:1000}") public void tick(){if(enabled)for(int i=0;i<20&&processNext();i++){} }
    public boolean processNext(){
        var job=outbox.claim();if(job==null)return false;String previous=MDC.get("traceId");
        try{
            if(job.trace()!=null)MDC.put("traceId",job.trace());
            if(!Instant.now().isBefore(job.expires())){outbox.complete(job,"EXPIRED");return true;}
            var payload=outbox.payload(job);
            if(job.kind().equals("RECOVERY"))accounts.forgotPassword(payload.path("email").asText());
            else{
                Map<String,String> variables=new HashMap<>();payload.path("variables").fields().forEachRemaining(e->variables.put(e.getKey(),e.getValue().asText()));
                mail.deliver(payload.path("to").asText(),payload.path("templateId").asText(),variables,job.id());
            }
            outbox.complete(job,"SENT");
        }catch(RuntimeException e){outbox.retry(job);SecurityAudit.record(SecurityAudit.Event.ACCOUNT_MAIL_FAILURE,SecurityAudit.Outcome.FAILURE,null,job.trace());}
        finally{if(previous==null)MDC.remove("traceId");else MDC.put("traceId",previous);}
        return true;
    }
}
