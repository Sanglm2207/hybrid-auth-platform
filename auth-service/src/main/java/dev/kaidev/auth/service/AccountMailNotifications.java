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
    public record CommittedAudit(UUID userId, SecurityAudit.Event event) {}
    private final MailServiceClient mail;
    public AccountMailNotifications(MailServiceClient mail) { this.mail = mail; }

    @TransactionalEventListener
    public void send(Notice notice) {
        try { mail.send(notice.to(), notice.templateId(), notice.variables()); }
        catch (RuntimeException e) {
            // The account transaction has committed; notification delivery cannot undo it.
            SecurityAudit.record(SecurityAudit.Event.ACCOUNT_MAIL_FAILURE, SecurityAudit.Outcome.FAILURE,
                    notice.userId().toString(), MDC.get("traceId"));
        }
    }
    @TransactionalEventListener
    public void audit(CommittedAudit event) {
        SecurityAudit.record(event.event(), SecurityAudit.Outcome.SUCCESS, event.userId().toString(), MDC.get("traceId"));
    }
}
