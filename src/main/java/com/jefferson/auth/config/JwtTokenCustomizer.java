package com.jefferson.auth.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    @Override
    public void customize(JwtEncodingContext context) {
        JwtClaimsSet.Builder claims = context.getClaims();

        if (context.getTokenType().getValue().equals("access_token")) {
            customizeAccessToken(claims, context);
        } else if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
            customizeIdToken(claims, context);
        }

        addCommonClaims(claims, context);
    }

    private void customizeAccessToken(JwtClaimsSet.Builder claims, JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();

        Set<String> authorities = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        claims.claim("authorities", authorities);
        claims.claim("roles", authorities);

        if (context.getAuthorizedScopes().contains("admin")) {
            claims.claim("admin", true);
        }

        // Add client information
        claims.claim("client_id", context.getRegisteredClient().getClientId());
        claims.claim("client_name", context.getRegisteredClient().getClientName());

        // Add token metadata
        claims.claim("token_type", "access_token");
        claims.claim("token_use", "access");
    }

    private void customizeIdToken(JwtClaimsSet.Builder claims, JwtEncodingContext context) {
        Authentication principal = context.getPrincipal();

        claims.claim("preferred_username", principal.getName());

        claims.claim("given_name", "User");
        claims.claim("family_name", "Name");
        claims.claim("name", principal.getName());
        claims.claim("picture", "https://via.placeholder.com/150");

        // Add additional profile information
        if (context.getAuthorizedScopes().contains("email")) {
            claims.claim("email", principal.getName() + "@example.com");
            claims.claim("email_verified", true);
        }

        if (context.getAuthorizedScopes().contains("profile")) {
            claims.claim("updated_at", Instant.now().getEpochSecond());
            claims.claim("locale", "en-US");
            claims.claim("zoneinfo", "America/New_York");
        }
    }

    private void addCommonClaims(JwtClaimsSet.Builder claims, JwtEncodingContext context) {
        // Add tenant information if multi-tenant
        // claims.claim("tenant_id", "default");

        // Add custom application claims
        claims.claim("application", "authorization-server");
        claims.claim("version", "1.0.0");

        // Add grant type
        claims.claim("grant_type", context.getAuthorizationGrantType().getValue());

        // Add authorized scopes
        claims.claim("scope", String.join(" ", context.getAuthorizedScopes()));

        // Add custom timestamps
        claims.claim("auth_time", Instant.now().getEpochSecond());
    }
}