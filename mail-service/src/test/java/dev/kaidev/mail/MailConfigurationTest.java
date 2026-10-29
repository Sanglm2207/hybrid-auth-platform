package dev.kaidev.mail;

import dev.kaidev.common.exception.ApiException;
import dev.kaidev.mail.config.MailProperties;
import dev.kaidev.mail.dto.SendMailRequest;
import dev.kaidev.mail.service.*;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {"app.mail.api-key=", "spring.mail.host=", "app.mail.from="})
@AutoConfigureMockMvc
class MailConfigurationTest {
    @Autowired MockMvc mvc;
    @Autowired MailTemplateService templates;

    @Test void missingKeyFailsClosedButHealthIsAvailable() throws Exception {
        mvc.perform(get("/api/v1/mail/templates")).andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("MAIL_NOT_CONFIGURED"));
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    @Test void missingSmtpConfigurationNeverCallsProvider() {
        var sender = mock(JavaMailSender.class);
        var delivery = new MailDeliveryService(sender, templates, new MailProperties("key", "", Map.of()), "");
        assertThatThrownBy(() -> delivery.send(new SendMailRequest("a@example.com", "email-verification",
                Map.of("otp", "123456", "expiresInMinutes", "5"))))
                .isInstanceOfSatisfying(ApiException.class, e -> assertThat(e.apiCode().name()).isEqualTo("MAIL_NOT_CONFIGURED"));
        verifyNoInteractions(sender);
    }

    @Test void brokenTemplateResourceFailsAtStartup() {
        var definition = new MailProperties.Template("Test", "classpath:missing.html", "classpath:missing.txt");
        assertThatThrownBy(() -> new MailTemplateService(new MailProperties("key", "sender@example.com",
                Map.of("broken", definition)), new DefaultResourceLoader())).isInstanceOf(java.io.IOException.class);
    }
}
