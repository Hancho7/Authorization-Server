package com.jefferson.auth.security.oAuthClient;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "oauth_clients")
public class OAuthClientEntity {

    @Id
    private String id;

    @Column(name = "client_id", unique = true, nullable = false)
    private String clientId;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "client_name")
    private String clientName;

    @Column(name = "client_secret_expires_at")
    private Instant clientSecretExpiresAt;

    // Changed from default varchar(255) to TEXT for large content
    @Column(name = "client_authentication_methods", columnDefinition = "TEXT")
    private String clientAuthenticationMethods;

    @Column(name = "authorization_grant_types", columnDefinition = "TEXT")
    private String authorizationGrantTypes;

    @Column(name = "redirect_uris", columnDefinition = "TEXT")
    private String redirectUris;

    @Column(name = "post_logout_redirect_uris", columnDefinition = "TEXT")
    private String postLogoutRedirectUris;

    @Column(name = "scopes", columnDefinition = "TEXT")
    private String scopes;

    // These are JSON strings that can be quite large
    @Column(name = "client_settings", columnDefinition = "TEXT")
    private String clientSettings;

    @Column(name = "token_settings", columnDefinition = "TEXT")
    private String tokenSettings;

    // Constructors, getters, setters...
    public OAuthClientEntity() {}

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getClientName() {
        return clientName;
    }

    public void setClientName(String clientName) {
        this.clientName = clientName;
    }

    public Instant getClientSecretExpiresAt() {
        return clientSecretExpiresAt;
    }

    public void setClientSecretExpiresAt(Instant clientSecretExpiresAt) {
        this.clientSecretExpiresAt = clientSecretExpiresAt;
    }

    public String getClientAuthenticationMethods() {
        return clientAuthenticationMethods;
    }

    public void setClientAuthenticationMethods(String clientAuthenticationMethods) {
        this.clientAuthenticationMethods = clientAuthenticationMethods;
    }

    public String getAuthorizationGrantTypes() {
        return authorizationGrantTypes;
    }

    public void setAuthorizationGrantTypes(String authorizationGrantTypes) {
        this.authorizationGrantTypes = authorizationGrantTypes;
    }

    public String getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(String redirectUris) {
        this.redirectUris = redirectUris;
    }

    public String getPostLogoutRedirectUris() {
        return postLogoutRedirectUris;
    }

    public void setPostLogoutRedirectUris(String postLogoutRedirectUris) {
        this.postLogoutRedirectUris = postLogoutRedirectUris;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public String getClientSettings() {
        return clientSettings;
    }

    public void setClientSettings(String clientSettings) {
        this.clientSettings = clientSettings;
    }

    public String getTokenSettings() {
        return tokenSettings;
    }

    public void setTokenSettings(String tokenSettings) {
        this.tokenSettings = tokenSettings;
    }
}