package dev.kaidev.auth.client;

import dev.kaidev.common.exception.ApiException;
import java.net.SocketTimeoutException;
import java.util.Map;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;
import org.springframework.http.*;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class MailServiceClientTest {
    private MockRestServiceServer server;
    private MailServiceClient client;
    private RestClient restClient;
    private final Map<String, String> variables = Map.of("otp", "123456", "expiresInMinutes", "5");

    @BeforeEach void setup() {
        var builder = RestClient.builder().baseUrl("http://mail.test");
        server = MockRestServiceServer.bindTo(builder).build();
        restClient = builder.build();
        client = new MailServiceClient(restClient, "test-key");
    }

    @AfterEach void cleanup() { MDC.clear(); server.verify(); }

    @Test void sendsTemplateRequestWithInternalKeyAndTrace() {
        MDC.put("correlationId", "12345678-1234-1234-1234-123456789abc");
        server.expect(requestTo("http://mail.test/api/v1/mail/send")).andExpect(method(HttpMethod.POST))
                .andExpect(header("X-Mail-Service-Key", "test-key"))
                .andExpect(header("X-Request-Id", MDC.get("correlationId")))
                .andExpect(content().json("""
                        {"to":"a@example.com","templateId":"email-verification","variables":{"otp":"123456","expiresInMinutes":"5"}}
                        """))
                .andRespond(withSuccess("{\"success\":true,\"code\":\"MAIL_SENT\"}", MediaType.APPLICATION_JSON));
        client.send("a@example.com", "email-verification", variables);
    }

    @Test void missingKeyDoesNotCallMailService() {
        var unconfigured = new MailServiceClient(restClient, "");
        assertThatThrownBy(() -> unconfigured.send("a@example.com", "email-verification", variables))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.apiCode().name()).isEqualTo("EMAIL_NOT_CONFIGURED"));
    }

    @ParameterizedTest @ValueSource(ints = {400, 401, 404, 500, 503})
    void upstreamErrorsAreMappedToSafeAuthFailure(int status) {
        server.expect(requestTo("http://mail.test/api/v1/mail/send"))
                .andRespond(withStatus(HttpStatusCode.valueOf(status)).body("secret-provider-detail"));
        assertDeliveryFailure();
    }

    @ParameterizedTest @ValueSource(strings = {"", "{}", "{\"success\":false,\"code\":\"MAIL_SENT\"}", "{\"success\":true,\"code\":\"OTHER\"}", "not-json"})
    void invalidAcknowledgementDoesNotReportSuccess(String json) {
        server.expect(requestTo("http://mail.test/api/v1/mail/send")).andRespond(withSuccess(json, MediaType.APPLICATION_JSON));
        assertDeliveryFailure();
    }

    @Test void timeoutReturnsSafeFailureWithoutAutomaticRetry() {
        server.expect(requestTo("http://mail.test/api/v1/mail/send")).andRespond(request -> { throw new SocketTimeoutException(); });
        assertDeliveryFailure();
    }

    private void assertDeliveryFailure() {
        assertThatThrownBy(() -> client.send("a@example.com", "email-verification", variables))
                .isInstanceOfSatisfying(ApiException.class, e -> {
                    assertThat(e.apiCode().name()).isEqualTo("EMAIL_DELIVERY_FAILED");
                    assertThat(e.getMessage()).doesNotContain("secret-provider-detail", "123456", "test-key");
                });
    }
}
