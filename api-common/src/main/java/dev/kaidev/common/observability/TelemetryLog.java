package dev.kaidev.common.observability;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.opentelemetry.api.trace.Span;
import java.time.Instant;
import java.util.*;
import org.slf4j.*;

/** Only explicitly constructed event fields enter the telemetry stream; no request bodies/headers. */
public final class TelemetryLog {
    private static final Logger LOG=LoggerFactory.getLogger("observability.events");
    private static final ObjectMapper JSON=new ObjectMapper();
    private TelemetryLog(){}
    public static void event(String event,String correlation,Map<String,?> attributes){
        var fields=new LinkedHashMap<String,Object>();fields.put("timestamp",Instant.now().toString());fields.put("event",event);
        var span=Span.current().getSpanContext();
        if(span.isValid()){fields.put("trace_id",span.getTraceId());fields.put("span_id",span.getSpanId());}
        try{if(correlation!=null)fields.put("correlation_id",UUID.fromString(correlation).toString());}catch(IllegalArgumentException ignored){}
        fields.putAll(attributes);
        try{LOG.info(JSON.writeValueAsString(fields));}catch(com.fasterxml.jackson.core.JsonProcessingException e){LOG.warn("{\"event\":\"telemetry.encoding.failed\"}");}
    }
}
