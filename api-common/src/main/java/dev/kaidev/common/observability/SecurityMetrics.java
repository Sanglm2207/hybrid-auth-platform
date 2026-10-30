package dev.kaidev.common.observability;

import dev.kaidev.common.security.SecurityAudit;
import io.micrometer.core.instrument.Metrics;
import java.util.Set;

/** Bounded labels only: never use subjects, addresses, raw paths or correlation IDs as metric labels. */
public final class SecurityMetrics {
    private SecurityMetrics(){}
    static { initialize(); }
    public static void initialize(){
        for(String outcome:Set.of("success","failure","error"))Metrics.counter("auth.login.attempts","outcome",outcome);
        Metrics.counter("auth.refresh.reuse.detected");Metrics.counter("auth.redis.connection.failures");
    }
    public static void audit(SecurityAudit.Event event,SecurityAudit.Outcome outcome){
        Metrics.counter("security.events","event",event.name(),"outcome",outcome.name()).increment();
        if(event==SecurityAudit.Event.REFRESH_REUSE)Metrics.counter("auth.refresh.reuse.detected").increment();
    }
    public static void login(int status){
        Metrics.counter("auth.login.attempts","outcome",status>=500?"error":status>=200&&status<300?"success":"failure").increment();
    }
    public static void redisFailure(boolean connection){
        Metrics.counter("auth.redis.operation.failures","reason",connection?"connection":"operation").increment();
        if(connection)Metrics.counter("auth.redis.connection.failures").increment();
    }
}
