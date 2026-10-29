package dev.kaidev.common.security;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.*;

class SecurityAuditTest {
    @Test void detailsAcceptOnlyControlledIdsAndPolicyFields() {
        String target=java.util.UUID.randomUUID().toString();
        var safe=SecurityAudit.safeDetails(java.util.Map.of("targetUserId",target,"password","secret","email","private@example.com",
                "rolesAfter",java.util.List.of("USER","password=secret"),"sessionId","token=secret"));
        assertThat(safe).containsEntry("targetUserId",target).containsEntry("rolesAfter",java.util.List.of("USER"));
        assertThat(safe.toString()).doesNotContain("secret","private@example.com");
    }

    @Test void auditIsJsonAndDoesNotAcceptCredentialsOrLogInjectionAsIdentity() throws Exception {
        var logger = (Logger) LoggerFactory.getLogger("security.audit");
        var captured = new ListAppender<ILoggingEvent>(); captured.start(); logger.addAppender(captured);
        try {
            SecurityAudit.record(SecurityAudit.Event.LOGIN, SecurityAudit.Outcome.DENIED,
                    "email@example.com\npassword=secret", "untrusted-trace\nsecret");
            String json = captured.list.getFirst().getFormattedMessage();
            var fields = new ObjectMapper().readTree(json);
            assertThat(fields.path("event").asText()).isEqualTo("LOGIN");
            assertThat(fields.path("outcome").asText()).isEqualTo("DENIED");
            assertThat(fields.path("actor").asText()).isEqualTo("anonymous");
            assertThat(fields.path("timestamp").asText()).isNotBlank();
            assertThat(json).doesNotContain("secret", "password", "email@example.com", "\n");
        } finally { logger.detachAppender(captured); captured.stop(); }
    }
}
