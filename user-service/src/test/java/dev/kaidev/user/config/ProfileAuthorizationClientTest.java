package dev.kaidev.user.config;

import com.sun.net.httpserver.HttpServer;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.IdentityCheck;
import dev.kaidev.user.security.UserIdentityClient;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class ProfileAuthorizationClientTest {
    @Test void parsesDecisionsAndFailsClosedOnMalformedUnavailableOrUnauthorizedPolicyService() throws Exception {
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        var response=new AtomicReference<>("{\"success\":true,\"data\":{\"allowed\":true}}");
        var request=new AtomicReference<String>();
        server.createContext("/internal/identity/authorize-profile",exchange->{
            assertThat(exchange.getRequestHeaders().getFirst("X-Identity-Service-Key")).isEqualTo("internal-service-key-at-least-32-characters");
            request.set(new String(exchange.getRequestBody().readAllBytes(),StandardCharsets.UTF_8));
            byte[] body=response.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type","application/json");exchange.sendResponseHeaders(200,body.length);
            try(var output=exchange.getResponseBody()){output.write(body);}
        });
        server.start();
        var identity=new IdentityCheck(UUID.randomUUID(),UUID.randomUUID(),1L,2L);
        UUID target=UUID.randomUUID(),tenant=UUID.randomUUID();String trace=UUID.randomUUID().toString();
        var client=new UserIdentityClient("http://127.0.0.1:"+server.getAddress().getPort(),"internal-service-key-at-least-32-characters");
        try {
            client.authorizeProfile(identity,target,tenant,"read",trace);
            assertThat(request.get()).contains(identity.subject().toString(),identity.sessionId().toString(),target.toString(),tenant.toString());
            response.set("{\"success\":true,\"data\":{\"allowed\":false}}");
            assertThatThrownBy(()->client.authorizeProfile(identity,target,tenant,"read",trace)).isInstanceOfSatisfying(ApiException.class,e->assertThat(e.apiCode().name()).isEqualTo("ACCESS_DENIED"));
            for(String invalid:new String[]{"{}","{\"success\":true,\"data\":{}}","not-json"}) {
                response.set(invalid);
                assertThatThrownBy(()->client.authorizeProfile(identity,target,tenant,"read",trace)).isInstanceOfSatisfying(ApiException.class,e->assertThat(e.apiCode().name()).isEqualTo("SERVICE_UNAVAILABLE"));
            }
        }finally {server.stop(0);}
        assertThatThrownBy(()->client.authorizeProfile(identity,target,tenant,"read",trace)).isInstanceOf(ApiException.class);
        assertThatThrownBy(()->new UserIdentityClient("http://localhost:1","").authorizeProfile(identity,target,tenant,"read",trace)).isInstanceOf(ApiException.class);
    }
}
