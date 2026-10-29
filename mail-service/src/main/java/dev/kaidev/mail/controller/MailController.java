package dev.kaidev.mail.controller;

import dev.kaidev.common.api.ApiPaths;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.api.response.ApiResponse;
import dev.kaidev.common.servlet.support.ServletApi;
import dev.kaidev.mail.constant.MailCode;
import dev.kaidev.mail.dto.*;
import dev.kaidev.mail.service.*;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(ApiPaths.MAIL_V1)
public class MailController {
    private final MailTemplateService templates;
    private final MailDeliveryService delivery;

    public MailController(MailTemplateService templates, MailDeliveryService delivery) {
        this.templates = templates;
        this.delivery = delivery;
    }

    @GetMapping("/templates")
    public ApiResponse<List<TemplateResponse>> templates() { return ServletApi.success(CommonCode.OK, templates.list()); }

    @PostMapping("/templates/{id}/preview")
    public ApiResponse<RenderedMail> preview(@PathVariable String id, @Valid @RequestBody PreviewMailRequest request) {
        return ServletApi.success(CommonCode.OK, templates.render(id, request.variables()));
    }

    @PostMapping("/send")
    public ApiResponse<Void> send(@Valid @RequestBody SendMailRequest request) {
        delivery.send(request);
        return ServletApi.success(MailCode.MAIL_SENT, null);
    }
}
