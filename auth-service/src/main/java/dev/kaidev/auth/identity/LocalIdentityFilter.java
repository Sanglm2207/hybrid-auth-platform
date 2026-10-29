package dev.kaidev.auth.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.kaidev.common.api.code.CommonCode;
import dev.kaidev.common.exception.ApiException;
import dev.kaidev.common.security.*;
import dev.kaidev.common.servlet.support.ServletApi;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

public class LocalIdentityFilter extends OncePerRequestFilter {
    private final IdentityValidationService identities;
    private final ObjectMapper mapper;
    public LocalIdentityFilter(IdentityValidationService identities, ObjectMapper mapper) { this.identities = identities; this.mapper = mapper; }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (SecurityContextHolder.getContext().getAuthentication() instanceof JwtAuthenticationToken authentication) {
            IdentityCheck check;
            try { check = IdentityCheck.fromClaims(authentication.getToken().getClaims()); }
            catch (RuntimeException e) { ServletApi.failure(request, response, mapper, CommonCode.UNAUTHENTICATED); return; }
            IdentityAccess access;
            try { access = identities.check(check); }
            catch (ApiException e) { ServletApi.failure(request, response, mapper, e.apiCode()); return; }
            catch (org.springframework.dao.DataAccessException e) { ServletApi.failure(request, response, mapper, CommonCode.SERVICE_UNAVAILABLE); return; }
            if (access == null || !access.active()) {
                SecurityAudit.record(SecurityAudit.Event.AUTHENTICATION_FAILURE, SecurityAudit.Outcome.DENIED,
                        authentication.getName(), ServletApi.traceId(request));
                ServletApi.failure(request, response, mapper, CommonCode.UNAUTHENTICATED); return;
            }
            SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(authentication.getToken(),
                    access.authorities().stream().map(SimpleGrantedAuthority::new).toList()));
        }
        chain.doFilter(request, response);
    }
}
