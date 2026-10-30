package dev.kaidev.auth.hardening;
import dev.kaidev.common.security.SecurityAudit;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.*;
import java.sql.Timestamp;
import java.time.Instant;
import org.slf4j.MDC;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.*;
@Component
public class AuthAuditStore {
    private final JdbcTemplate jdbc;private final ObjectMapper json;
    public AuthAuditStore(JdbcTemplate jdbc,ObjectMapper json){this.jdbc=jdbc;this.json=json;}
    @Transactional(propagation=Propagation.MANDATORY)
    public void append(UUID actor,SecurityAudit.Event event,Map<String,?> details){
        var safe=SecurityAudit.safeDetails(details);
        UUID target=safe.containsKey("targetUserId")?UUID.fromString(safe.get("targetUserId").toString()):null;
        String trace=MDC.get("correlationId");try{if(trace!=null)trace=UUID.fromString(trace).toString();}catch(IllegalArgumentException e){trace=null;}
        try{jdbc.update("insert into security_audit_records(id,created_at,event,actor,target,details,trace_id) values(?,?,?,?,?,?,?)",UUID.randomUUID(),Timestamp.from(Instant.now()),event.name(),actor,target,json.writeValueAsString(safe),trace);}
        catch(com.fasterxml.jackson.core.JsonProcessingException e){throw new IllegalStateException("Audit serialization failed");}
    }
}
