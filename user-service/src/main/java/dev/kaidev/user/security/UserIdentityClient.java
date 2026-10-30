package dev.kaidev.user.security;

import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.*;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.*;

@Component
public class UserIdentityClient {
    private final RestClient client;
    private final String key;
    public UserIdentityClient(String url,String key){this(url,key,RestClient.builder());}
    @org.springframework.beans.factory.annotation.Autowired
    public UserIdentityClient(@Value("${app.identity.url}") String url, @Value("${app.identity.api-key:}") String key,RestClient.Builder builder) {
        this.key = key;
        var factory = new SimpleClientHttpRequestFactory(); factory.setConnectTimeout(Duration.ofSeconds(2)); factory.setReadTimeout(Duration.ofSeconds(3));
        client = builder.clone().baseUrl(url).requestFactory(factory).build();
    }
    public IdentityAccess check(IdentityCheck request, String trace) {
        if (key.length() < 32) throw new ApiException(CommonCode.SERVICE_UNAVAILABLE);
        try {
            var response = client.post().uri("/internal/identity/check").contentType(MediaType.APPLICATION_JSON)
                    .header("X-Identity-Service-Key", key).header("X-Request-Id", trace).body(request)
                    .retrieve().body(new ParameterizedTypeReference<ApiResponse<IdentityAccess>>() {});
            if (response == null || !response.success() || response.data() == null || response.data().roles() == null || response.data().permissions() == null)
                throw new ApiException(CommonCode.SERVICE_UNAVAILABLE);
            return response.data();
        } catch (RestClientException e) { throw new ApiException(CommonCode.SERVICE_UNAVAILABLE); }
    }
    public void authorizeProfile(IdentityCheck identity,java.util.UUID target,java.util.UUID tenant,String action,String trace){
        if(key.length()<32)throw new ApiException(CommonCode.SERVICE_UNAVAILABLE);
        var body=new java.util.HashMap<String,Object>();body.put("identity",identity);body.put("target",target);body.put("tenant",tenant);body.put("action",action);
        try {
            var response=client.post().uri("/internal/identity/authorize-profile").contentType(MediaType.APPLICATION_JSON)
                    .header("X-Identity-Service-Key",key).header("X-Request-Id",trace).body(body).retrieve()
                    .body(new ParameterizedTypeReference<ApiResponse<java.util.Map<String,Boolean>>>(){});
            if(response==null||!response.success()||response.data()==null||!response.data().containsKey("allowed"))throw new ApiException(CommonCode.SERVICE_UNAVAILABLE);
            if(!Boolean.TRUE.equals(response.data().get("allowed")))throw new ApiException(CommonCode.ACCESS_DENIED);
        }catch(RestClientException e){throw new ApiException(CommonCode.SERVICE_UNAVAILABLE);}
    }
}
