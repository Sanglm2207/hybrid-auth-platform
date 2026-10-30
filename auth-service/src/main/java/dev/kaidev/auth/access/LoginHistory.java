package dev.kaidev.auth.access;

import dev.kaidev.common.servlet.support.VerifiedClientAddress;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.*;
import org.springframework.web.context.request.*;

@Service
public class LoginHistory {
    public record Entry(UUID id,Instant occurredAt,boolean successful,String reason,String ip,String userAgent) {
        @Override public String toString(){return "AuthenticationHistory[REDACTED]";}
    }
    private final JdbcTemplate jdbc;
    private final String proxyKey;
    public LoginHistory(JdbcTemplate jdbc,@Value("${app.auth-proxy-key:}") String key){this.jdbc=jdbc;this.proxyKey=key;}
    // Failed login rolls back its enclosing transaction. History must survive that rollback.
    @Transactional(propagation=Propagation.REQUIRES_NEW)
    public void record(UUID user,boolean success,String reason) { write(user,success,reason); }
    @Transactional(propagation=Propagation.MANDATORY)
    public void successful(UUID user){write(user,true,"SUCCESS");}
    private void write(UUID user,boolean success,String reason) {
        var attributes=RequestContextHolder.getRequestAttributes(); String ip="unknown",agent="unknown";
        if(attributes instanceof ServletRequestAttributes current) {
            ip=VerifiedClientAddress.resolve(current.getRequest(),proxyKey);
            String value=current.getRequest().getHeader("User-Agent");
            if(value!=null){String cleaned=value.replaceAll("[\\p{Cntrl}]","");agent=cleaned.substring(0,Math.min(256,cleaned.length()));}
        }
        jdbc.update("insert into authentication_history(id,user_id,occurred_at,successful,reason,ip,user_agent) values(?,?,?,?,?,?,?)",
                UUID.randomUUID(),user,Timestamp.from(Instant.now()),success,reason,ip,agent);
    }
    public List<Entry> list(UUID owner,Instant from,Instant to,Boolean success,int page,int size) {
        if(from==null)from=Instant.now().minusSeconds(30L*86400); if(to==null)to=Instant.now();
        if(from.isAfter(to)||page<0||page>10000||size<1||size>100)throw new dev.kaidev.common.exception.ApiException(dev.kaidev.common.api.code.CommonCode.INVALID_REQUEST);
        String condition=success==null?"":" and successful=?";
        var args=new ArrayList<Object>(List.of(owner,Timestamp.from(from),Timestamp.from(to)));
        if(success!=null)args.add(success);args.add(size);args.add(page*size);
        return jdbc.query("select * from authentication_history where user_id=? and occurred_at>=? and occurred_at<=?"+condition+" order by occurred_at desc,id limit ? offset ?",
                (r,n)->new Entry(r.getObject("id",UUID.class),r.getTimestamp("occurred_at").toInstant(),r.getBoolean("successful"),r.getString("reason"),r.getString("ip"),r.getString("user_agent")),args.toArray());
    }
}
