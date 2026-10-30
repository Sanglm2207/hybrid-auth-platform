package dev.kaidev.auth.access;

import com.fasterxml.jackson.databind.JsonNode;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import java.time.Duration;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.*;

@Component
public class ProfileDataClient {
    private final RestClient client;private final String key;
    @org.springframework.beans.factory.annotation.Autowired
    public ProfileDataClient(@Value("${app.user-service.url:http://127.0.0.1:8702}")String url,@Value("${app.identity.api-key:}")String key,RestClient.Builder builder){
        this.key=key;var factory=new SimpleClientHttpRequestFactory();factory.setConnectTimeout(Duration.ofSeconds(2));factory.setReadTimeout(Duration.ofSeconds(3));
        client=builder.clone().baseUrl(url).requestFactory(factory).build();
    }
    public JsonNode export(UUID owner){
        configured();try {
            var value=client.get().uri("/internal/users/{id}/profile",owner).header("X-Identity-Service-Key",key).retrieve().body(JsonNode.class);
            if(value==null||!value.path("success").asBoolean()||!value.has("data"))throw new ApiException(CommonCode.SERVICE_UNAVAILABLE);
            return value.path("data");
        }catch(RestClientException e){throw new ApiException(CommonCode.SERVICE_UNAVAILABLE);}
    }
    public void delete(UUID owner){
        configured();try {
            var value=client.delete().uri("/internal/users/{id}/profile",owner).header("X-Identity-Service-Key",key).retrieve().body(JsonNode.class);
            if(value==null||!value.path("success").asBoolean())throw new ApiException(CommonCode.SERVICE_UNAVAILABLE);
        }catch(RestClientException e){throw new ApiException(CommonCode.SERVICE_UNAVAILABLE);}
    }
    private void configured(){if(key.length()<32)throw new ApiException(CommonCode.SERVICE_UNAVAILABLE);}
}
