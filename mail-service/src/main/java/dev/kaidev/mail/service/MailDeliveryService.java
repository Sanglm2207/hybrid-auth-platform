package dev.kaidev.mail.service;

import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.logging.ApiLog;
import dev.kaidev.mail.config.MailProperties;
import dev.kaidev.mail.constant.MailCode;
import dev.kaidev.mail.dto.SendMailRequest;
import jakarta.mail.MessagingException;
import java.nio.charset.StandardCharsets;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class MailDeliveryService {
    private final JavaMailSender sender;
    private final MailTemplateService templates;
    private final MailProperties properties;
    private final String host;

    public MailDeliveryService(JavaMailSender sender, MailTemplateService templates, MailProperties properties,
            @Value("${spring.mail.host}") String host) {
        this.sender = sender;
        this.templates = templates;
        this.properties = properties;
        this.host = host;
    }

    public void send(SendMailRequest request) { send(request,java.util.UUID.randomUUID()); }
    public void send(SendMailRequest request, java.util.UUID id) {
        var rendered = templates.render(request.templateId(), request.variables());
        if (host.isBlank() || properties.from() == null || properties.from().isBlank())
            throw new ApiException(MailCode.MAIL_NOT_CONFIGURED);
        try {
            var message = sender.createMimeMessage();
            var helper = new MimeMessageHelper(message, true, StandardCharsets.UTF_8.name());
            helper.setFrom(properties.from());
            helper.setTo(request.to());
            helper.setSubject(rendered.subject());
            helper.setText(rendered.text(), rendered.html());
            message.setHeader("Message-ID","<"+id+"@hybrid-auth.local>");
            sender.send(message);
            ApiLog.event(org.slf4j.LoggerFactory.getLogger(MailDeliveryService.class), "mail.sent", MailCode.MAIL_SENT.name());
        } catch (MailException | MessagingException e) {
            ApiLog.failure(MailCode.MAIL_DELIVERY_FAILED.name(), e, MDC.get("traceId"));
            throw new ApiException(MailCode.MAIL_DELIVERY_FAILED);
        }
    }
}
