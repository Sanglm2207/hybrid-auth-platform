package dev.kaidev.gateway.integration;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.*;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import static org.mockito.Mockito.*;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT,properties={
        "app.gateway.allowed-hosts=localhost,127.0.0.1,[::1]",
        "app.gateway.allowed-origins=https://client.example.com",
        "app.identity.api-key=gateway-test-identity-key-at-least-32-chars"})
class GatewayAccountRoutingTest {
    static HttpServer auth,user;
    static final AtomicReference<String> permissions=new AtomicReference<>();
    static final AtomicReference<String> forwardedProof=new AtomicReference<>();
    @DynamicPropertySource static void upstreams(DynamicPropertyRegistry properties) throws Exception {
        auth=server("auth");user=server("user");
        properties.add("AUTH_URL",()->"http://127.0.0.1:"+auth.getAddress().getPort());
        properties.add("USER_URL",()->"http://127.0.0.1:"+user.getAddress().getPort());
        properties.add("app.identity.url",()->"http://127.0.0.1:"+auth.getAddress().getPort());
    }
    static HttpServer server(String backend) throws Exception {
        var server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        server.createContext("/",exchange->{
            exchange.getRequestBody().readAllBytes();
            String body;
            if(exchange.getRequestURI().getPath().equals("/internal/identity/check"))
                body="{\"success\":true,\"data\":{\"active\":true,\"roles\":[\"USER\"],\"permissions\":"+permissions.get()+"}}";
            else {
                forwardedProof.set(exchange.getRequestHeaders().getFirst("X-Reauthentication-Token"));
                body="{\"backend\":\""+backend+"\"}";
            }
            byte[] bytes=body.getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type","application/json");
            exchange.sendResponseHeaders(200,bytes.length);try(var output=exchange.getResponseBody()){output.write(bytes);}
        });server.start();return server;
    }
    @AfterAll static void stop(){if(auth!=null)auth.stop(0);if(user!=null)user.stop(0);}
    @Autowired WebTestClient client;
    @MockitoBean ReactiveJwtDecoder decoder;
    @BeforeEach void identity(){
        permissions.set("[\"profile:read\",\"profile:write\",\"account:export\",\"account:delete\"]");
        when(decoder.decode("valid")).thenReturn(Mono.just(Jwt.withTokenValue("valid").header("alg","RS256")
                .subject(UUID.randomUUID().toString()).claim("sid",UUID.randomUUID().toString()).claim("cv",0L).claim("sv",0L).build()));
    }
    @Test void accountRoutesReachAuthAndProfileRoutesStillReachUser(){
        client.get().uri("/api/v1/users/me/export").headers(h->h.setBearerAuth("valid")).header("X-Reauthentication-Token","test-proof")
                .exchange().expectStatus().isOk().expectBody().jsonPath("$.backend").isEqualTo("auth");
        org.assertj.core.api.Assertions.assertThat(forwardedProof.get()).isEqualTo("test-proof");
        client.delete().uri("/api/v1/users/me").headers(h->h.setBearerAuth("valid"))
                .exchange().expectStatus().isOk().expectBody().jsonPath("$.backend").isEqualTo("auth");
        client.get().uri("/api/v1/users/me").headers(h->h.setBearerAuth("valid"))
                .exchange().expectStatus().isOk().expectBody().jsonPath("$.backend").isEqualTo("user");
        client.patch().uri("/api/v1/users/me").headers(h->h.setBearerAuth("valid"))
                .exchange().expectStatus().isOk().expectBody().jsonPath("$.backend").isEqualTo("user");
    }
    @Test void profilePermissionsCannotAuthorizeAccountExportOrDeletion(){
        permissions.set("[\"profile:read\",\"profile:write\"]");
        client.get().uri("/api/v1/users/me/export").headers(h->h.setBearerAuth("valid")).exchange().expectStatus().isForbidden();
        client.delete().uri("/api/v1/users/me").headers(h->h.setBearerAuth("valid")).exchange().expectStatus().isForbidden();
        client.get().uri("/api/v1/users/me/export").exchange().expectStatus().isUnauthorized();
    }
    @Test void approvedCorsAllowsReauthenticationHeader(){
        client.options().uri("/api/v1/users/me/export").header(HttpHeaders.ORIGIN,"https://client.example.com")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD,"GET")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS,"authorization,x-reauthentication-token")
                .exchange().expectStatus().isNoContent();
    }
}
