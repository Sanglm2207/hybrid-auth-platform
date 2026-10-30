package dev.kaidev.auth.hardening;

import io.micrometer.core.instrument.*;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** SQL snapshot, not a Redis index size; gauges never perform database I/O on the exporter thread. */
@Component
public class SessionMetrics {
    private final JdbcTemplate jdbc;
    private final AtomicReference<Double> active=new AtomicReference<>(Double.NaN);
    private final AtomicReference<Double> available=new AtomicReference<>(0d);
    public SessionMetrics(JdbcTemplate jdbc,MeterRegistry registry){
        this.jdbc=jdbc;
        Gauge.builder("auth.active.sessions",active,AtomicReference::get).description("Authoritative SQL active session snapshot per Auth instance").register(registry);
        Gauge.builder("auth.active.sessions.available",available,AtomicReference::get).register(registry);
    }
    @Scheduled(fixedDelayString="${app.observability.session-poll-ms:15000}",initialDelayString="${app.observability.session-poll-ms:15000}")
    public void refresh(){
        try{
            Long count=jdbc.queryForObject("select count(*) from identity_sessions s join app_users u on u.id=s.user_id where s.revoked_at is null and s.expires_at>CURRENT_TIMESTAMP and u.active=true and u.admin_locked=false and u.deleted_at is null and u.email_verified=true and s.generation=u.session_generation and s.credential_revision=u.credential_revision",Long.class);
            active.set(count.doubleValue());available.set(1d);
        }catch(org.springframework.dao.DataAccessException e){active.set(Double.NaN);available.set(0d);}
    }
}
