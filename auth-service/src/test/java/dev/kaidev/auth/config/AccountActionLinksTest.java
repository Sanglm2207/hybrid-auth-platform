package dev.kaidev.auth.config;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class AccountActionLinksTest {
    @Test void linksUseFixedOriginAndKeepProofOutOfHttpRequests() {
        var links = new AccountActionLinks("https://accounts.example.com/");
        var uri = java.net.URI.create(links.reset("a".repeat(43)));
        assertThat(uri.getHost()).isEqualTo("accounts.example.com");
        assertThat(uri.getPath()).isEqualTo("/api/v1/auth/reset-password");
        assertThat(uri.getQuery()).isNull();
        assertThat(uri.getFragment()).isEqualTo("token=" + "a".repeat(43));
        assertThat(links.confirmEmail("b".repeat(43))).contains("/confirm-email-change#token=");
    }

    @Test void rejectsUntrustedOriginShapesAndInvalidProofs() {
        for (String origin : java.util.List.of("http://accounts.example.com", "https://user@accounts.example.com",
                "https://accounts.example.com/path", "https://accounts.example.com?next=evil", "https://accounts.example.com#bad", "javascript:alert(1)")) {
            assertThatThrownBy(() -> new AccountActionLinks(origin)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> new AccountActionLinks("http://localhost:8700").reset("bad#token"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
