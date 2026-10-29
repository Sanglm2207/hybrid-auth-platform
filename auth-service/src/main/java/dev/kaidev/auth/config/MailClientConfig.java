package dev.kaidev.auth.config;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
public class MailClientConfig {
    @Bean
    RestClient mailRestClient(RestClient.Builder builder, @Value("${app.mail-service.url}") String url) {
        var factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(2));
        factory.setReadTimeout(Duration.ofSeconds(20));
        return builder.baseUrl(url).requestFactory(factory).build();
    }
}
