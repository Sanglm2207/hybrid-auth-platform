package dev.kaidev.auth.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.slf4j.MDC;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.*;

@Service
public class AuthOutbox {
    public record Job(UUID id,String kind,String encrypted,String trace,int attempts,Instant expires){@Override public String toString(){return "OutboxJob[REDACTED]";}}
    private final JdbcTemplate jdbc;private final OutboxCrypto crypto;private final ObjectMapper json;
    public AuthOutbox(JdbcTemplate jdbc,OutboxCrypto crypto,ObjectMapper json){this.jdbc=jdbc;this.crypto=crypto;this.json=json;}
    @Transactional public UUID mail(String to,String template,Map<String,String> variables){
        long ttl=template.equals("email-verification")?300:(template.equals("password-reset")||template.equals("email-change-verification")?900:86400);
        return enqueue("MAIL",Map.of("to",to,"templateId",template,"variables",variables),ttl);
    }
    @Transactional public UUID recovery(String email){return enqueue("RECOVERY",Map.of("email",email),900);}
    private UUID enqueue(String kind,Object payload,long ttl){try{
        UUID id=UUID.randomUUID();Instant now=Instant.now();String encrypted=crypto.encrypt(kind+":"+id,json.writeValueAsString(payload));
        jdbc.update("insert into auth_outbox(id,kind,encrypted_payload,trace_id,state,attempts,created_at,available_at,expires_at) values(?,?,?,?,?,0,?,?,?)",
                id,kind,encrypted,MDC.get("traceId"),"PENDING",Timestamp.from(now),Timestamp.from(now),Timestamp.from(now.plusSeconds(ttl)));return id;
    }catch(com.fasterxml.jackson.core.JsonProcessingException e){throw new IllegalStateException("Outbox serialization failed");}
    catch(org.springframework.dao.DataAccessException e){throw new dev.kaidev.common.exception.ApiException(dev.kaidev.auth.constant.AuthCode.SECURITY_UNAVAILABLE);}}
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public Job claim(){
        var jobs=jdbc.query("select * from auth_outbox where state in ('PENDING','PROCESSING') and available_at<=CURRENT_TIMESTAMP order by created_at limit 1 for update skip locked",
                (rs,n)->new Job(rs.getObject("id",UUID.class),rs.getString("kind"),rs.getString("encrypted_payload"),rs.getString("trace_id"),rs.getInt("attempts"),rs.getTimestamp("expires_at").toInstant()));
        if(jobs.isEmpty())return null;var job=jobs.getFirst();
        jdbc.update("update auth_outbox set state='PROCESSING',attempts=attempts+1,available_at=? where id=?",Timestamp.from(Instant.now().plusSeconds(120)),job.id());return job;
    }
    public com.fasterxml.jackson.databind.JsonNode payload(Job job){try{return json.readTree(crypto.decrypt(job.kind()+":"+job.id(),job.encrypted()));}catch(Exception e){throw new IllegalStateException("Invalid encrypted job payload");}}
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public void complete(Job job,String state){jdbc.update("update auth_outbox set state=?,completed_at=?,encrypted_payload='',error_code=null where id=? and state='PROCESSING' and attempts=?",state,Timestamp.from(Instant.now()),job.id(),job.attempts()+1);}
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public void retry(Job job){
        boolean dead=job.attempts()+1>=12||Instant.now().isAfter(job.expires());
        jdbc.update("update auth_outbox set state=?,available_at=?,error_code='DELIVERY_FAILED' where id=? and state='PROCESSING' and attempts=?",
                dead?"FAILED":"PENDING",Timestamp.from(Instant.now().plusSeconds(Math.min(300,1L<<Math.min(8,job.attempts()+1)))),job.id(),job.attempts()+1);
    }
}
