package dev.kaidev.auth.client;

import dev.kaidev.auth.constant.AuthCode;
import dev.kaidev.common.api.ApiPaths;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.logging.ApiLog;
import dev.kaidev.common.trace.RequestTrace;
import java.util.Map;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.*;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.*;

@Component
public class MailServiceClient {
    private final dev.kaidev.auth.outbox.AuthOutbox outbox;
    private final RestClient client;
    private final String apiKey;

    @org.springframework.beans.factory.annotation.Autowired
    public MailServiceClient(@Qualifier("mailRestClient") RestClient client,
            @Value("${app.mail-service.api-key}") String apiKey, dev.kaidev.auth.outbox.AuthOutbox outbox) {
        this.outbox = outbox;
        this.client = client;
        this.apiKey = apiKey;
    }

    public MailServiceClient(RestClient client,String apiKey){this(client,apiKey,null);}
    public void send(String to, String templateId, Map<String, String> variables) {
        if(outbox!=null){outbox.mail(to,templateId,variables);return;}
        deliver(to,templateId,variables,java.util.UUID.randomUUID());
    }
    public void deliver(String to,String templateId,Map<String,String> variables,java.util.UUID deliveryId){
        if (apiKey.isBlank()) throw new ApiException(AuthCode.EMAIL_NOT_CONFIGURED);
        try {
            var response = client.post().uri(ApiPaths.MAIL_V1 + "/send")
                    .contentType(MediaType.APPLICATION_JSON)
                    .header("X-Mail-Service-Key", apiKey).header("Idempotency-Key",deliveryId.toString())
                    .headers(headers -> {
                        String traceId = MDC.get("traceId");
                        if (traceId != null) headers.set(RequestTrace.HEADER, traceId);
                    })
                    .body(new MailRequest(to, templateId, variables))
                    .retrieve().body(new ParameterizedTypeReference<ApiResponse<Void>>() {});
            if (response == null || !response.success() || !"MAIL_SENT".equals(response.code()))
                throw new ApiException(AuthCode.EMAIL_DELIVERY_FAILED);
        } catch (RestClientException e) {
            // Provider responses, request variables, credentials and OTPs must stay out of logs and API errors.
            ApiLog.failure(AuthCode.EMAIL_DELIVERY_FAILED.name(), e, MDC.get("traceId"));
            throw new ApiException(AuthCode.EMAIL_DELIVERY_FAILED);
        }
    }

    private record MailRequest(String to, String templateId, Map<String, String> variables) {
        @Override public String toString() { return "MailRequest[REDACTED]"; }
    }
}
