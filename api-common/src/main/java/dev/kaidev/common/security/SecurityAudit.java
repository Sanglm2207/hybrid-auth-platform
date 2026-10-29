package dev.kaidev.common.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.UUID;
import org.slf4j.LoggerFactory;

/** Structured events deliberately exclude passwords, email addresses, IPs and tokens. */
public final class SecurityAudit {
    public enum Event { LOGIN, LOGOUT, LOGOUT_ALL, REFRESH, REFRESH_REUSE, ACCOUNT_LOCKED,
        RATE_LIMITED, AUTHENTICATION_FAILURE, ACCESS_DENIED, SECURITY_STATE_FAILURE, JWT_KEYS_RELOADED }
    public enum Outcome { SUCCESS, FAILURE, DENIED, UNAVAILABLE }
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private SecurityAudit() {}

    public static void record(Event event, Outcome outcome, String actor, String traceId) {
        String safeActor = "anonymous";
        try { if (actor != null) safeActor = UUID.fromString(actor).toString(); }
        catch (IllegalArgumentException ignored) { }
        String safeTrace = null;
        try { if (traceId != null) safeTrace = UUID.fromString(traceId).toString(); }
        catch (IllegalArgumentException ignored) { }
        var fields = new LinkedHashMap<String, Object>();
        fields.put("timestamp", Instant.now().toString());
        fields.put("event", event.name());
        fields.put("outcome", outcome.name());
        fields.put("actor", safeActor);
        fields.put("traceId", safeTrace);
        try { LoggerFactory.getLogger("security.audit").info("{}", MAPPER.writeValueAsString(fields)); }
        catch (com.fasterxml.jackson.core.JsonProcessingException ignored) {
            LoggerFactory.getLogger("security.audit").error("{\"event\":\"AUDIT_SERIALIZATION_FAILURE\"}");
        }
    }
}
