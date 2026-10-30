package dev.kaidev.auth.service;

import dev.kaidev.auth.client.MailServiceClient;
import dev.kaidev.common.security.SecurityAudit;
import java.util.Map;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class AccountMailNotifications {
    public record Notice(UUID userId, String to, String templateId, Map<String, String> variables) {
        @Override public String toString() { return "AccountNotice[REDACTED]"; }
    }
    public record CommittedAudit(UUID userId, SecurityAudit.Event event, Map<String,?> details) {
        public CommittedAudit(UUID userId, SecurityAudit.Event event) { this(userId,event,Map.of("targetUserId",userId)); }
    }
    private final MailServiceClient mail;
    private final dev.kaidev.auth.hardening.AuthAuditStore store;
    public AccountMailNotifications(MailServiceClient mail, dev.kaidev.auth.hardening.AuthAuditStore store) { this.mail = mail; this.store=store; }
    @TransactionalEventListener(phase=org.springframework.transaction.event.TransactionPhase.BEFORE_COMMIT)
    public void persist(CommittedAudit event) { store.append(event.userId(),event.event(),event.details()); }

    @TransactionalEventListener(phase=org.springframework.transaction.event.TransactionPhase.BEFORE_COMMIT)
    public void send(Notice notice) {
        mail.send(notice.to(),notice.templateId(),notice.variables());
    }
    @TransactionalEventListener
    public void audit(CommittedAudit event) {
        SecurityAudit.record(event.event(), SecurityAudit.Outcome.SUCCESS, event.userId().toString(), MDC.get("correlationId"),event.details());
    }
}
