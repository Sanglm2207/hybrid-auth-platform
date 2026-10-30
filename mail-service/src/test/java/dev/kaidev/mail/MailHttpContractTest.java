package dev.kaidev.mail;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kaidev.mail.dto.RenderedMail;
import jakarta.mail.*;
import jakarta.mail.internet.MimeMessage;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {"app.mail.api-key=test-mail-key", "spring.mail.host=smtp.test", "app.mail.from=Team <sender@example.com>"})
@AutoConfigureMockMvc
class MailHttpContractTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @MockitoBean JavaMailSender sender;
    private static final String KEY = "X-Mail-Service-Key";
    private static final String SEND = "/api/v1/mail/send";
    private static final String REQUEST = """
            {"to":" TEST@EXAMPLE.COM ","templateId":"email-verification","variables":{"otp":"123456","expiresInMinutes":"5"}}
            """;

    @BeforeEach void setup() {
        when(sender.createMimeMessage()).thenAnswer(call -> new MimeMessage(Session.getInstance(new Properties())));
    }

    @Test void internalApiRequiresExactlyOneValidServiceKey() throws Exception {
        mvc.perform(get("/api/v1/mail/templates")).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
        mvc.perform(post(SEND).header(KEY, "wrong").contentType(MediaType.APPLICATION_JSON).content(REQUEST))
                .andExpect(status().isUnauthorized());
        mvc.perform(post(SEND).header(KEY, "test-mail-key", "test-mail-key")
                .contentType(MediaType.APPLICATION_JSON).content(REQUEST)).andExpect(status().isUnauthorized());
        verify(sender, never()).send(any(MimeMessage.class));
    }

    @Test void healthRemainsAvailableWithoutServiceKey() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk()).andExpect(jsonPath("$.status").value("UP"));
    }

    @Test void listsConfiguredTemplatesAndTheirRequiredVariables() throws Exception {
        String json = mvc.perform(get("/api/v1/mail/templates").header(KEY, "test-mail-key"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        var templates = mapper.readTree(json).path("data");
        assertThat(templates.size()).isEqualTo(10);
        for (var template : templates) {
            assertThat(template.path("variables").toString()).doesNotContain("signature");
            if (template.path("id").asText().equals("email-verification"))
                assertThat(template.path("variables").toString()).contains("otp", "expiresInMinutes");
        }
    }

    @Test void previewEscapesHtmlAndDoesNotRecursivelyExpandCallerValues() throws Exception {
        String name = "<script>alert(1)</script> & {{appName}} $1";
        String json = mapper.writeValueAsString(Map.of("variables", Map.of("displayName", name, "appName", "Demo")));
        var result = mvc.perform(post("/api/v1/mail/templates/welcome/preview").header(KEY, "test-mail-key")
                .contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.subject").value("Welcome to Demo"))
                .andReturn().getResponse().getContentAsString();
        var data = mapper.readTree(result).path("data");
        assertThat(data.path("html").asText()).contains("&lt;script&gt;", "&amp;", "{{appName}} $1").doesNotContain("<script>");
        assertThat(data.path("text").asText()).contains(name);
        verify(sender, never()).send(any(MimeMessage.class));
    }

    @Test void sendProducesUtf8MultipartHtmlWithTextAlternativeAndTraceId() throws Exception {
        String trace = "12345678-1234-1234-1234-123456789abc";
        mvc.perform(post(SEND).header(KEY, "test-mail-key").header("X-Request-Id", trace)
                .contentType(MediaType.APPLICATION_JSON).content(REQUEST))
                .andExpect(status().isOk()).andExpect(jsonPath("$.code").value("MAIL_SENT"))
                .andExpect(jsonPath("$.traceId").value(trace)).andExpect(header().string("X-Request-Id", trace));
        var captor = ArgumentCaptor.forClass(MimeMessage.class);
        verify(sender).send(captor.capture());
        var message = captor.getValue();
        message.saveChanges();
        assertThat(message.getAllRecipients()[0].toString()).isEqualTo("test@example.com");
        assertThat(message.getSubject()).isEqualTo("Verify your email");
        assertThat(message.isMimeType("multipart/*")).isTrue();
        assertThat(body(message, "text/plain")).contains("123456", "5 minutes");
        assertThat(body(message, "text/html")).contains("<html", "123456", "Hybrid Auth Security Team");
        assertThat(body(message, "text/plain")).contains("Best regards", "Hybrid Auth Security Team");
    }

    @Test void retryUsesDurableReceiptAndMismatchedReuseIsRejected() throws Exception {
        String id=java.util.UUID.randomUUID().toString();
        for(int i=0;i<2;i++) mvc.perform(post(SEND).header(KEY,"test-mail-key").header("Idempotency-Key",id)
                .contentType(MediaType.APPLICATION_JSON).content(REQUEST)).andExpect(status().isOk());
        verify(sender,times(1)).send(any(MimeMessage.class));
        mvc.perform(post(SEND).header(KEY,"test-mail-key").header("Idempotency-Key",id)
                .contentType(MediaType.APPLICATION_JSON).content(REQUEST.replace("123456","654321"))).andExpect(status().isConflict());
        verify(sender,times(1)).send(any(MimeMessage.class));
    }
    @Test void failedSmtpDoesNotMarkReceiptSentAndRetryCanDeliver() throws Exception {
        String id=java.util.UUID.randomUUID().toString();
        doThrow(new MailAuthenticationException("provider-secret")).doNothing().when(sender).send(any(MimeMessage.class));
        mvc.perform(post(SEND).header(KEY,"test-mail-key").header("Idempotency-Key",id)
                .contentType(MediaType.APPLICATION_JSON).content(REQUEST)).andExpect(status().isServiceUnavailable());
        mvc.perform(post(SEND).header(KEY,"test-mail-key").header("Idempotency-Key",id)
                .contentType(MediaType.APPLICATION_JSON).content(REQUEST)).andExpect(status().isOk());
        verify(sender,times(2)).send(any(MimeMessage.class));
    }

    private static String body(Part part, String mimeType) throws Exception {
        if (part.isMimeType(mimeType)) return part.getContent().toString();
        if (part.getContent() instanceof Multipart multipart) {
            for (int i = 0; i < multipart.getCount(); i++) {
                String found = body(multipart.getBodyPart(i), mimeType);
                if (found != null) return found;
            }
        }
        return null;
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"to\":\"invalid\",\"templateId\":\"welcome\",\"variables\":{}}",
            "{\"to\":\"a@example.com\",\"templateId\":\"../welcome\",\"variables\":{}}",
            "{\"to\":\"a@example.com\",\"templateId\":\"welcome\",\"variables\":null}",
            "{\"to\":\"a@example.com\",\"templateId\":\"welcome\",\"variables\":{\"appName\":5}}",
            "{\"to\":\"a@example.com\",\"templateId\":\"welcome\",\"variables\":{},\"html\":\"injected\"}"
    })
    void invalidRequestsNeverSendMail(String json) throws Exception {
        mvc.perform(post(SEND).header(KEY, "test-mail-key").contentType(MediaType.APPLICATION_JSON).content(json))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.success").value(false));
        verify(sender, never()).send(any(MimeMessage.class));
    }

    @Test void unknownTemplateAndInvalidVariablesNeverSendMail() throws Exception {
        mvc.perform(post(SEND).header(KEY, "test-mail-key").contentType(MediaType.APPLICATION_JSON)
                .content(REQUEST.replace("email-verification", "missing")))
                .andExpect(status().isNotFound()).andExpect(jsonPath("$.code").value("TEMPLATE_NOT_FOUND"));
        for (var variables : java.util.List.of(Map.of("otp", "123456"),
                Map.of("otp", "123456", "expiresInMinutes", "5", "extra", "value"))) {
            mvc.perform(post(SEND).header(KEY, "test-mail-key").contentType(MediaType.APPLICATION_JSON)
                    .content(mapper.writeValueAsString(Map.of("to", "a@example.com", "templateId", "email-verification", "variables", variables))))
                    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("TEMPLATE_VARIABLES_INVALID"));
        }
        mvc.perform(post("/api/v1/mail/templates/welcome/preview").header(KEY, "test-mail-key")
                .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(
                        Map.of("variables", Map.of("appName", "Demo\r\nBcc: hidden@example.com", "displayName", "User")))))
                .andExpect(status().isBadRequest());
        verify(sender, never()).send(any(MimeMessage.class));
    }

    @Test void everyLifecycleTemplateRendersSignedHtmlAndTextWithoutCallerSignatureOverride() throws Exception {
        Map<String, Map<String, String>> examples = Map.of(
                "password-reset", Map.of("resetUrl", "https://app.example.com/api/v1/auth/reset-password#token=" + "a".repeat(43), "expiresInMinutes", "15"),
                "password-changed", Map.of(),
                "account-deactivated", Map.of(),
                "roles-changed", Map.of(),
                "email-change-verification", Map.of("verificationUrl", "https://app.example.com/api/v1/auth/confirm-email-change#token=" + "b".repeat(43), "expiresInMinutes", "15"),
                "email-change-requested", Map.of("newEmail", "new@example.com"),
                "email-changed", Map.of("newEmail", "new@example.com"),
                "email-change-confirmed", Map.of());
        for (var example : examples.entrySet()) {
            var json = mvc.perform(post("/api/v1/mail/templates/" + example.getKey() + "/preview").header(KEY, "test-mail-key")
                    .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(Map.of("variables", example.getValue()))))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
            var rendered = mapper.readTree(json).path("data");
            assertThat(rendered.path("html").asText()).contains("Best regards", "Hybrid Auth Security Team").doesNotContain("{{");
            assertThat(rendered.path("text").asText()).contains("Best regards", "Hybrid Auth Security Team").doesNotContain("{{");
        }
        mvc.perform(post("/api/v1/mail/templates/password-changed/preview").header(KEY, "test-mail-key")
                .contentType(MediaType.APPLICATION_JSON).content("{\"variables\":{\"signature\":\"Fake sender\"}}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("TEMPLATE_VARIABLES_INVALID"));
        verify(sender, never()).send(any(MimeMessage.class));
    }

    @Test void actionEmailsRenderButtonsAndRejectUnsafeLinkSchemes() throws Exception {
        for (String template : java.util.List.of("password-reset", "email-change-verification")) {
            String variable = template.equals("password-reset") ? "resetUrl" : "verificationUrl";
            String link = "https://accounts.example.com/action#token=" + "a".repeat(43);
            var result = mvc.perform(post("/api/v1/mail/templates/" + template + "/preview").header(KEY, "test-mail-key")
                    .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(Map.of("variables",
                            Map.of(variable, link, "expiresInMinutes", "15")))))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
            var rendered = mapper.readTree(result).path("data");
            assertThat(rendered.path("html").asText()).contains("href=\"" + link + "\"")
                    .doesNotContain("one-time token", "reset token", "font-family:monospace");
            assertThat(rendered.path("text").asText()).contains(link).doesNotContain("one-time token");
            for (String unsafe : java.util.List.of("javascript:alert(1)", "data:text/html,bad", "//evil.example.com", "http://evil.example.com")) {
                mvc.perform(post("/api/v1/mail/templates/" + template + "/preview").header(KEY, "test-mail-key")
                        .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsString(Map.of("variables",
                                Map.of(variable, unsafe, "expiresInMinutes", "15")))))
                        .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("TEMPLATE_VARIABLES_INVALID"));
            }
        }
    }

    @Test void smtpErrorsNeverExposeProviderDetailsOrOtp() throws Exception {
        doThrow(new MailAuthenticationException("secret-provider-detail")).when(sender).send(any(MimeMessage.class));
        String response = mvc.perform(post(SEND).header(KEY, "test-mail-key")
                .contentType(MediaType.APPLICATION_JSON).content(REQUEST))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.code").value("MAIL_DELIVERY_FAILED"))
                .andReturn().getResponse().getContentAsString();
        assertThat(response).doesNotContain("secret-provider-detail", "123456", "test-mail-key");
    }
}
