package com.jefferson.auth.security.oAuthClient;

import com.jefferson.auth.commons.exceptions.ClientAlreadyExistsException;
import com.jefferson.auth.commons.exceptions.ClientNotFoundException;
import com.jefferson.auth.commons.exceptions.ClientOperationException;
import com.jefferson.auth.commons.exceptions.InvalidClientDataException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Service
@Transactional
@Validated
public class OAuthClientService {

    private final OAuthClientJpaRepository jpaRepository;
    private final CustomRegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;

    public OAuthClientService(OAuthClientJpaRepository jpaRepository,
                              CustomRegisteredClientRepository registeredClientRepository,
                              PasswordEncoder passwordEncoder) {
        this.jpaRepository = jpaRepository;
        this.registeredClientRepository = registeredClientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Page<OAuthClientEntity> getAllClients(Pageable pageable) {
        return jpaRepository.findAll(pageable);
    }

    public Optional<OAuthClientEntity> getClientById(String id) {
        return jpaRepository.findById(id);
    }

    public OAuthClientEntity getClientByClientId(String clientId) {
        OAuthClientEntity client = jpaRepository.findByClientId(clientId);
        if (client == null) {
            throw new ClientNotFoundException("Client not found with client ID: " + clientId);
        }
        return client;
    }

    public OAuthClientEntity createClient(@Valid CreateClientRequest request) {
        // Auto-generate clientId if not provided
        if (!StringUtils.hasText(request.getClientId())) {
            request.setClientId(UUID.randomUUID().toString());
        }

        // Validate unique client ID
        if (jpaRepository.findByClientId(request.getClientId()) != null) {
            throw new ClientAlreadyExistsException("Client ID already exists: " + request.getClientId());
        }
        // Validate required fields
        validateCreateRequest(request);

        // Validate unique client ID
        if (jpaRepository.findByClientId(request.getClientId()) != null) {
            throw new ClientAlreadyExistsException("Client ID already exists: " + request.getClientId());
        }

        try {
            // Create RegisteredClient
            RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(request.getClientId())
                    .clientName(request.getClientName());

            // Set client secret if provided
            if (StringUtils.hasText(request.getClientSecret())) {
                builder.clientSecret(passwordEncoder.encode(request.getClientSecret()));
            }

            // Set authentication methods
            if (request.getClientAuthenticationMethods() != null && !request.getClientAuthenticationMethods().isEmpty()) {
                request.getClientAuthenticationMethods().forEach(method ->
                        builder.clientAuthenticationMethod(resolveClientAuthenticationMethod(method)));
            } else {
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            }

            // Set grant types
            if (request.getAuthorizationGrantTypes() != null && !request.getAuthorizationGrantTypes().isEmpty()) {
                request.getAuthorizationGrantTypes().forEach(grantType ->
                        builder.authorizationGrantType(resolveAuthorizationGrantType(grantType)));
            } else {
                builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
            }

            // Set redirect URIs
            if (request.getRedirectUris() != null && !request.getRedirectUris().isEmpty()) {
                request.getRedirectUris().forEach(builder::redirectUri);
            }

            // Set post logout redirect URIs
            if (request.getPostLogoutRedirectUris() != null && !request.getPostLogoutRedirectUris().isEmpty()) {
                request.getPostLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);
            }

            // Set scopes
            if (request.getScopes() != null && !request.getScopes().isEmpty()) {
                request.getScopes().forEach(builder::scope);
            }

            // Set client settings
            ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder();
            if (request.getRequireAuthorizationConsent() != null) {
                clientSettingsBuilder.requireAuthorizationConsent(request.getRequireAuthorizationConsent());
            }
            if (request.getRequireProofKey() != null) {
                clientSettingsBuilder.requireProofKey(request.getRequireProofKey());
            }
            builder.clientSettings(clientSettingsBuilder.build());

            // Set token settings
            TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();
            if (request.getAccessTokenTimeToLive() != null && request.getAccessTokenTimeToLive() > 0) {
                tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofSeconds(request.getAccessTokenTimeToLive()));
            }
            if (request.getRefreshTokenTimeToLive() != null && request.getRefreshTokenTimeToLive() > 0) {
                tokenSettingsBuilder.refreshTokenTimeToLive(Duration.ofSeconds(request.getRefreshTokenTimeToLive()));
            }
            if (request.getReuseRefreshTokens() != null) {
                tokenSettingsBuilder.reuseRefreshTokens(request.getReuseRefreshTokens());
            }
            builder.tokenSettings(tokenSettingsBuilder.build());

            RegisteredClient registeredClient = builder.build();

            // Save to repository
            registeredClientRepository.save(registeredClient);

            // Return the entity
            return jpaRepository.findByClientId(registeredClient.getClientId());
        } catch (Exception e) {
            throw new ClientOperationException("Failed to create client: " + e.getMessage(), e);
        }
    }

    public OAuthClientEntity updateClient(String id, @Valid UpdateClientRequest request) {
        Optional<OAuthClientEntity> existingEntity = jpaRepository.findById(id);
        if (existingEntity.isEmpty()) {
            throw new ClientNotFoundException("Client not found with id: " + id);
        }

        try {
            // Get the existing RegisteredClient
            RegisteredClient existingClient = registeredClientRepository.findById(id);
            if (existingClient == null) {
                throw new ClientNotFoundException("RegisteredClient not found with id: " + id);
            }

            // Build updated client
            RegisteredClient.Builder builder = RegisteredClient.from(existingClient);

            if (StringUtils.hasText(request.getClientName())) {
                builder.clientName(request.getClientName());
            }

            if (StringUtils.hasText(request.getClientSecret())) {
                builder.clientSecret(passwordEncoder.encode(request.getClientSecret()));
            }

            if (request.getRedirectUris() != null && !request.getRedirectUris().isEmpty()) {
                builder.redirectUris(uris -> {
                    uris.clear();
                    uris.addAll(request.getRedirectUris());
                });
            }

            if (request.getPostLogoutRedirectUris() != null && !request.getPostLogoutRedirectUris().isEmpty()) {
                builder.postLogoutRedirectUris(uris -> {
                    uris.clear();
                    uris.addAll(request.getPostLogoutRedirectUris());
                });
            }

            if (request.getScopes() != null && !request.getScopes().isEmpty()) {
                builder.scopes(scopes -> {
                    scopes.clear();
                    scopes.addAll(request.getScopes());
                });
            }

            // Update client settings
            ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder();
            if (request.getRequireAuthorizationConsent() != null) {
                clientSettingsBuilder.requireAuthorizationConsent(request.getRequireAuthorizationConsent());
            }
            if (request.getRequireProofKey() != null) {
                clientSettingsBuilder.requireProofKey(request.getRequireProofKey());
            }
            builder.clientSettings(clientSettingsBuilder.build());

            // Update token settings
            TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();
            if (request.getAccessTokenTimeToLive() != null && request.getAccessTokenTimeToLive() > 0) {
                tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofSeconds(request.getAccessTokenTimeToLive()));
            }
            if (request.getRefreshTokenTimeToLive() != null && request.getRefreshTokenTimeToLive() > 0) {
                tokenSettingsBuilder.refreshTokenTimeToLive(Duration.ofSeconds(request.getRefreshTokenTimeToLive()));
            }
            if (request.getReuseRefreshTokens() != null) {
                tokenSettingsBuilder.reuseRefreshTokens(request.getReuseRefreshTokens());
            }
            builder.tokenSettings(tokenSettingsBuilder.build());

            RegisteredClient updatedClient = builder.build();
            registeredClientRepository.save(updatedClient);

            return jpaRepository.findById(id).orElseThrow(() ->
                    new ClientNotFoundException("Client not found after update: " + id));
        } catch (ClientNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new ClientOperationException("Failed to update client: " + e.getMessage(), e);
        }
    }

    public void deleteClient(String id) {
        if (!jpaRepository.existsById(id)) {
            throw new ClientNotFoundException("Client not found with id: " + id);
        }

        try {
            jpaRepository.deleteById(id);
        } catch (Exception e) {
            throw new ClientOperationException("Failed to delete client: " + e.getMessage(), e);
        }
    }

    public List<OAuthClientEntity> searchClients(String clientName, String clientId) {
        // Enhanced search logic - you can implement custom queries
        if (StringUtils.hasText(clientId)) {
            OAuthClientEntity client = jpaRepository.findByClientId(clientId);
            return client != null ? List.of(client) : List.of();
        }
        // For now, return all - you can enhance this with custom queries
        return jpaRepository.findAll();
    }

    private void validateCreateRequest(CreateClientRequest request) {
        if (!StringUtils.hasText(request.getClientId())) {
            throw new InvalidClientDataException("Client ID is required");
        }

        if (!StringUtils.hasText(request.getClientName())) {
            throw new InvalidClientDataException("Client name is required");
        }

        // Validate redirect URIs for authorization_code grant
        if (request.getAuthorizationGrantTypes() != null &&
                request.getAuthorizationGrantTypes().contains("authorization_code")) {
            if (request.getRedirectUris() == null || request.getRedirectUris().isEmpty()) {
                throw new InvalidClientDataException("Redirect URIs are required for authorization_code grant");
            }
        }
    }

    private ClientAuthenticationMethod resolveClientAuthenticationMethod(String method) {
        return switch (method.toLowerCase()) {
            case "client_secret_basic" -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
            case "client_secret_post" -> ClientAuthenticationMethod.CLIENT_SECRET_POST;
            case "none" -> ClientAuthenticationMethod.NONE;
            case "private_key_jwt" -> ClientAuthenticationMethod.PRIVATE_KEY_JWT;
            case "client_secret_jwt" -> ClientAuthenticationMethod.CLIENT_SECRET_JWT;
            case "tls_client_auth" -> ClientAuthenticationMethod.TLS_CLIENT_AUTH;
            case "self_signed_tls_client_auth" -> ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH;
            default -> new ClientAuthenticationMethod(method);
        };
    }

    private AuthorizationGrantType resolveAuthorizationGrantType(String grantType) {
        return switch (grantType.toLowerCase()) {
            case "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE;
            case "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS;
            case "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN;
            case "urn:ietf:params:oauth:grant-type:device_code" -> AuthorizationGrantType.DEVICE_CODE;
            case "urn:ietf:params:oauth:grant-type:token-exchange" -> AuthorizationGrantType.TOKEN_EXCHANGE;
            default -> new AuthorizationGrantType(grantType);
        };
    }

    // Enhanced DTOs with validation
    public static class CreateClientRequest {
        @NotBlank(message = "Client ID is required")
        private String clientId;

        @NotBlank(message = "Client name is required")
        private String clientName;

        private String clientSecret;
        private Set<String> clientAuthenticationMethods;
        private Set<String> authorizationGrantTypes;
        private Set<String> redirectUris;
        private Set<String> postLogoutRedirectUris;
        private Set<String> scopes;
        private Boolean requireAuthorizationConsent;
        private Boolean requireProofKey;
        private Long accessTokenTimeToLive;
        private Long refreshTokenTimeToLive;
        private Boolean reuseRefreshTokens;

        // Getters and setters
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }

        public String getClientName() { return clientName; }
        public void setClientName(String clientName) { this.clientName = clientName; }

        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

        public Set<String> getClientAuthenticationMethods() { return clientAuthenticationMethods; }
        public void setClientAuthenticationMethods(Set<String> clientAuthenticationMethods) { this.clientAuthenticationMethods = clientAuthenticationMethods; }

        public Set<String> getAuthorizationGrantTypes() { return authorizationGrantTypes; }
        public void setAuthorizationGrantTypes(Set<String> authorizationGrantTypes) { this.authorizationGrantTypes = authorizationGrantTypes; }

        public Set<String> getRedirectUris() { return redirectUris; }
        public void setRedirectUris(Set<String> redirectUris) { this.redirectUris = redirectUris; }

        public Set<String> getPostLogoutRedirectUris() { return postLogoutRedirectUris; }
        public void setPostLogoutRedirectUris(Set<String> postLogoutRedirectUris) { this.postLogoutRedirectUris = postLogoutRedirectUris; }

        public Set<String> getScopes() { return scopes; }
        public void setScopes(Set<String> scopes) { this.scopes = scopes; }

        public Boolean getRequireAuthorizationConsent() { return requireAuthorizationConsent; }
        public void setRequireAuthorizationConsent(Boolean requireAuthorizationConsent) { this.requireAuthorizationConsent = requireAuthorizationConsent; }

        public Boolean getRequireProofKey() { return requireProofKey; }
        public void setRequireProofKey(Boolean requireProofKey) { this.requireProofKey = requireProofKey; }

        public Long getAccessTokenTimeToLive() { return accessTokenTimeToLive; }
        public void setAccessTokenTimeToLive(Long accessTokenTimeToLive) { this.accessTokenTimeToLive = accessTokenTimeToLive; }

        public Long getRefreshTokenTimeToLive() { return refreshTokenTimeToLive; }
        public void setRefreshTokenTimeToLive(Long refreshTokenTimeToLive) { this.refreshTokenTimeToLive = refreshTokenTimeToLive; }

        public Boolean getReuseRefreshTokens() { return reuseRefreshTokens; }
        public void setReuseRefreshTokens(Boolean reuseRefreshTokens) { this.reuseRefreshTokens = reuseRefreshTokens; }
    }

    public static class UpdateClientRequest {
        private String clientName;
        private String clientSecret;
        private Set<String> redirectUris;
        private Set<String> postLogoutRedirectUris;
        private Set<String> scopes;
        private Boolean requireAuthorizationConsent;
        private Boolean requireProofKey;
        private Long accessTokenTimeToLive;
        private Long refreshTokenTimeToLive;
        private Boolean reuseRefreshTokens;

        // Getters and setters
        public String getClientName() { return clientName; }
        public void setClientName(String clientName) { this.clientName = clientName; }

        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

        public Set<String> getRedirectUris() { return redirectUris; }
        public void setRedirectUris(Set<String> redirectUris) { this.redirectUris = redirectUris; }

        public Set<String> getPostLogoutRedirectUris() { return postLogoutRedirectUris; }
        public void setPostLogoutRedirectUris(Set<String> postLogoutRedirectUris) { this.postLogoutRedirectUris = postLogoutRedirectUris; }

        public Set<String> getScopes() { return scopes; }
        public void setScopes(Set<String> scopes) { this.scopes = scopes; }

        public Boolean getRequireAuthorizationConsent() { return requireAuthorizationConsent; }
        public void setRequireAuthorizationConsent(Boolean requireAuthorizationConsent) { this.requireAuthorizationConsent = requireAuthorizationConsent; }

        public Boolean getRequireProofKey() { return requireProofKey; }
        public void setRequireProofKey(Boolean requireProofKey) { this.requireProofKey = requireProofKey; }

        public Long getAccessTokenTimeToLive() { return accessTokenTimeToLive; }
        public void setAccessTokenTimeToLive(Long accessTokenTimeToLive) { this.accessTokenTimeToLive = accessTokenTimeToLive; }

        public Long getRefreshTokenTimeToLive() { return refreshTokenTimeToLive; }
        public void setRefreshTokenTimeToLive(Long refreshTokenTimeToLive) { this.refreshTokenTimeToLive = refreshTokenTimeToLive; }

        public Boolean getReuseRefreshTokens() { return reuseRefreshTokens; }
        public void setReuseRefreshTokens(Boolean reuseRefreshTokens) { this.reuseRefreshTokens = reuseRefreshTokens; }
    }
}