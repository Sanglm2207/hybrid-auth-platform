package dev.kaidev.common.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.UUID;
import org.slf4j.LoggerFactory;

/**
 * Structured events deliberately exclude passwords, email addresses, IPs and
 * tokens.
 */
public final class SecurityAudit {
    public enum Event {
        SESSION_REVOKED, DEVICE_REVOKED, ROLES_CHANGED, ROLE_POLICY_CHANGED, ACCOUNT_DEACTIVATED, PROFILE_UPDATED,
        LOGIN, LOGOUT, LOGOUT_ALL, REFRESH, REFRESH_REUSE, ACCOUNT_LOCKED,
        PASSWORD_RESET_REQUESTED, PASSWORD_RESET, PASSWORD_CHANGED, EMAIL_CHANGE_REQUESTED, EMAIL_CHANGED,
        ACCOUNT_MAIL_FAILURE, ACCOUNT_RECOVERY_FAILURE,
        RATE_LIMITED, AUTHENTICATION_FAILURE, ACCESS_DENIED, SECURITY_STATE_FAILURE, JWT_KEYS_RELOADED
    }

    public enum Outcome {
        SUCCESS, FAILURE, DENIED, UNAVAILABLE
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SecurityAudit() {
    }

    public static java.util.Map<String,Object> safeDetails(java.util.Map<String,?> input) {
        var result=new java.util.TreeMap<String,Object>();
        input.forEach((key,value)->{
            if (java.util.Set.of("targetUserId","sessionId","deviceId").contains(key)) {
                try { result.put(key,UUID.fromString(String.valueOf(value)).toString()); } catch(IllegalArgumentException ignored) {}
            } else if (key.equals("role") && value instanceof String text && text.matches("[A-Z][A-Z0-9_]{0,31}")) result.put(key,text);
            else if (java.util.Set.of("rolesBefore","rolesAfter","permissionsBefore","permissionsAfter").contains(key) && value instanceof java.util.Collection<?> items && items.size()<=64) {
                var safe=items.stream().map(String::valueOf).filter(v->v.matches("[A-Z][A-Z0-9_]{0,31}|[a-z]+:[a-z]+" )).sorted().toList();
                result.put(key,safe);
            }
        });
        return java.util.Map.copyOf(result);
    }
    public static void record(Event event, Outcome outcome, String actor, String traceId) {
        record(event,outcome,actor,traceId,java.util.Map.of());
    }
    public static void record(Event event, Outcome outcome, String actor, String traceId, java.util.Map<String,?> details) {
        String safeActor = "anonymous";
        try {
            if (actor != null)
                safeActor = UUID.fromString(actor).toString();
        } catch (IllegalArgumentException ignored) {
        }
        String safeTrace = null;
        try {
            if (traceId != null)
                safeTrace = UUID.fromString(traceId).toString();
        } catch (IllegalArgumentException ignored) {
        }
        var fields = new LinkedHashMap<String, Object>();
        fields.put("timestamp", Instant.now().toString());
        fields.put("event", event.name());
        fields.put("outcome", outcome.name());
        fields.put("actor", safeActor);
        fields.put("traceId", safeTrace);
        fields.put("details", safeDetails(details));
        try {
            LoggerFactory.getLogger("security.audit").info("{}", MAPPER.writeValueAsString(fields));
        } catch (com.fasterxml.jackson.core.JsonProcessingException ignored) {
            LoggerFactory.getLogger("security.audit").error("{\"event\":\"AUDIT_SERIALIZATION_FAILURE\"}");
        }
    }
}
