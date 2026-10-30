package dev.kaidev.common.observability;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kaidev.common.security.SecurityAudit;
import io.micrometer.core.instrument.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.opentelemetry.api.trace.*;
import org.junit.jupiter.api.*;
import org.slf4j.LoggerFactory;
import java.util.Map;
import static org.assertj.core.api.Assertions.*;

class TelemetryTest {
    @Test void correlatesTraceAndRequestWithoutIncludingAuditIdentityOrUncontrolledDetails() throws Exception {
        var logger=(Logger)LoggerFactory.getLogger("observability.events");var appender=new ListAppender<ILoggingEvent>();appender.start();logger.addAppender(appender);
        var span=Span.wrap(SpanContext.create("1234567890abcdef1234567890abcdef","1234567890abcdef",TraceFlags.getSampled(),TraceState.getDefault()));
        try(var scope=span.makeCurrent()){
            SecurityAudit.record(SecurityAudit.Event.REFRESH_REUSE,SecurityAudit.Outcome.DENIED,"11111111-1111-4111-8111-111111111111","22222222-2222-4222-8222-222222222222",Map.of("password","never-include-password","email","private@example.com"));
            String json=appender.list.getFirst().getFormattedMessage();var event=new ObjectMapper().readTree(json);
            assertThat(event.path("trace_id").asText()).isEqualTo("1234567890abcdef1234567890abcdef");
            assertThat(event.path("span_id").asText()).isEqualTo("1234567890abcdef");
            assertThat(event.path("correlation_id").asText()).isEqualTo("22222222-2222-4222-8222-222222222222");
            assertThat(json).doesNotContain("never-include-password","private@example.com","11111111-1111-4111-8111-111111111111");
        }finally{logger.detachAppender(appender);appender.stop();}
    }
    @Test void countsReplayAndLoginOutcomesWithBoundedLabels(){
        var registry=new SimpleMeterRegistry();Metrics.addRegistry(registry);
        try{
            SecurityMetrics.login(200);SecurityMetrics.login(401);SecurityMetrics.login(429);SecurityMetrics.login(503);
            SecurityMetrics.audit(SecurityAudit.Event.REFRESH_REUSE,SecurityAudit.Outcome.DENIED);SecurityMetrics.redisFailure(true);
            assertThat(registry.get("auth.login.attempts").tag("outcome","success").counter().count()).isEqualTo(1);
            assertThat(registry.get("auth.login.attempts").tag("outcome","failure").counter().count()).isEqualTo(2);
            assertThat(registry.get("auth.login.attempts").tag("outcome","error").counter().count()).isEqualTo(1);
            assertThat(registry.get("auth.refresh.reuse.detected").counter().count()).isEqualTo(1);
            assertThat(registry.get("auth.redis.connection.failures").counter().count()).isEqualTo(1);
            assertThat(registry.getMeters()).allSatisfy(m->assertThat(m.getId().getTags()).noneMatch(t->t.getKey().matches("user|email|trace_id|uri")));
        }finally{Metrics.removeRegistry(registry);registry.close();}
    }
}
