package dev.kaidev.auth.controller;

import dev.kaidev.common.api.ApiPaths;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(ApiPaths.AUTH_V1)
public class AccountActionPageController {
    @GetMapping(value = {"/forgot-password", "/reset-password", "/confirm-email-change"}, produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<Resource> page() {
        return resource("account-actions.html", MediaType.TEXT_HTML);
    }

    @GetMapping("/account-actions.js")
    public ResponseEntity<Resource> script() {
        return resource("account-actions.js", MediaType.parseMediaType("text/javascript"));
    }

    private ResponseEntity<Resource> resource(String name, MediaType type) {
        return ResponseEntity.ok().contentType(type).cacheControl(CacheControl.noStore())
                .header("Referrer-Policy", "no-referrer")
                .header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
                .body(new ClassPathResource("account-pages/" + name));
    }
}
