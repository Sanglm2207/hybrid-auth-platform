package dev.kaidev.common.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Deliberately excludes bodies, headers, credentials, OTPs, and exception messages. */
public final class ApiLog {
    private static final Logger LOG = LoggerFactory.getLogger(ApiLog.class);
    private ApiLog() {}
    public static void completed(String method, int status, long elapsedMs, String traceId) {
        dev.kaidev.common.observability.TelemetryLog.event("http.request.completed",traceId,java.util.Map.of("method",method,"status",status,"duration_ms",elapsedMs));
        LOG.info("event=request.completed method={} status={} durationMs={} traceId={}", method, status, elapsedMs, traceId);
    }
    public static void failure(String code, Throwable error, String traceId) {
        dev.kaidev.common.observability.TelemetryLog.event("http.request.failed",traceId,java.util.Map.of("code",code,"exception_type",error.getClass().getSimpleName()));
        LOG.error("event=request.failed code={} exceptionType={} traceId={}", code, error.getClass().getSimpleName(), traceId);
    }
    public static void event(Logger logger, String event, String code) {
        logger.info("event={} code={} traceId={}", event, code, org.slf4j.MDC.get("correlationId"));
    }
}
