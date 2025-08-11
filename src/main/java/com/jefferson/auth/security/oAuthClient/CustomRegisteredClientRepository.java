package com.jefferson.auth.security.oAuthClient;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.util.Set;

@Component
public class CustomRegisteredClientRepository implements RegisteredClientRepository {

    private final OAuthClientJpaRepository jpaRepository;

    public CustomRegisteredClientRepository(OAuthClientJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");

        OAuthClientEntity entity = jpaRepository.findByClientId(registeredClient.getClientId());
        if (entity == null) {
            entity = new OAuthClientEntity();
        }

        entity.setId(registeredClient.getId());
        entity.setClientId(registeredClient.getClientId());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientName(registeredClient.getClientName());
        entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());

        // Store as comma-delimited strings
        entity.setClientAuthenticationMethods(
                StringUtils.collectionToCommaDelimitedString(
                        registeredClient.getClientAuthenticationMethods().stream()
                                .map(ClientAuthenticationMethod::getValue)
                                .toList()
                )
        );

        entity.setAuthorizationGrantTypes(
                StringUtils.collectionToCommaDelimitedString(
                        registeredClient.getAuthorizationGrantTypes().stream()
                                .map(AuthorizationGrantType::getValue)
                                .toList()
                )
        );

        entity.setRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
        entity.setPostLogoutRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris()));
        entity.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));

        // Store settings as simple string representations
        entity.setClientSettings(serializeClientSettings(registeredClient.getClientSettings()));
        entity.setTokenSettings(serializeTokenSettings(registeredClient.getTokenSettings()));

        jpaRepository.save(entity);
    }

    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return jpaRepository.findById(id).map(this::mapToRegisteredClient).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        OAuthClientEntity entity = jpaRepository.findByClientId(clientId);
        return entity != null ? mapToRegisteredClient(entity) : null;
    }

    private RegisteredClient mapToRegisteredClient(OAuthClientEntity entity) {
        Set<String> clientAuthenticationMethods = StringUtils.commaDelimitedListToSet(entity.getClientAuthenticationMethods());
        Set<String> authorizationGrantTypes = StringUtils.commaDelimitedListToSet(entity.getAuthorizationGrantTypes());
        Set<String> redirectUris = StringUtils.commaDelimitedListToSet(entity.getRedirectUris());
        Set<String> postLogoutRedirectUris = StringUtils.commaDelimitedListToSet(entity.getPostLogoutRedirectUris());
        Set<String> clientScopes = StringUtils.commaDelimitedListToSet(entity.getScopes());

        RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId())
                .clientId(entity.getClientId())
                .clientName(entity.getClientName())
                .clientSecret(entity.getClientSecret());

        if (entity.getClientSecretExpiresAt() != null) {
            builder.clientSecretExpiresAt(entity.getClientSecretExpiresAt());
        }

        // Map client authentication methods
        clientAuthenticationMethods.forEach(method ->
                builder.clientAuthenticationMethod(resolveClientAuthenticationMethod(method)));

        // Map authorization grant types
        authorizationGrantTypes.forEach(grantType ->
                builder.authorizationGrantType(resolveAuthorizationGrantType(grantType)));

        // Map redirect URIs
        builder.redirectUris(uris -> uris.addAll(redirectUris));

        // Map post logout redirect URIs
        if (!postLogoutRedirectUris.isEmpty()) {
            builder.postLogoutRedirectUris(uris -> uris.addAll(postLogoutRedirectUris));
        }

        // Map scopes
        builder.scopes(scopes -> scopes.addAll(clientScopes));

        // Deserialize settings
        builder.clientSettings(deserializeClientSettings(entity.getClientSettings()));
        builder.tokenSettings(deserializeTokenSettings(entity.getTokenSettings()));

        return builder.build();
    }

    private String serializeClientSettings(ClientSettings clientSettings) {
        StringBuilder sb = new StringBuilder();
        sb.append("requireAuthorizationConsent:").append(clientSettings.isRequireAuthorizationConsent());
        sb.append(",requireProofKey:").append(clientSettings.isRequireProofKey());
        return sb.toString();
    }

    private String serializeTokenSettings(TokenSettings tokenSettings) {
        StringBuilder sb = new StringBuilder();
        sb.append("accessTokenTTL:").append(tokenSettings.getAccessTokenTimeToLive().getSeconds());
        sb.append(",refreshTokenTTL:").append(tokenSettings.getRefreshTokenTimeToLive().getSeconds());
        sb.append(",authorizationCodeTTL:").append(tokenSettings.getAuthorizationCodeTimeToLive().getSeconds());
        return sb.toString();
    }

    private ClientSettings deserializeClientSettings(String data) {
        ClientSettings.Builder builder = ClientSettings.builder();

        if (StringUtils.hasText(data)) {
            String[] pairs = data.split(",");
            for (String pair : pairs) {
                String[] keyValue = pair.split(":");
                if (keyValue.length == 2) {
                    String key = keyValue[0].trim();
                    String value = keyValue[1].trim();

                    switch (key) {
                        case "requireAuthorizationConsent":
                            builder.requireAuthorizationConsent(Boolean.parseBoolean(value));
                            break;
                        case "requireProofKey":
                            builder.requireProofKey(Boolean.parseBoolean(value));
                            break;
                    }
                }
            }
        }

        return builder.build();
    }

    private TokenSettings deserializeTokenSettings(String data) {
        TokenSettings.Builder builder = TokenSettings.builder();

        if (StringUtils.hasText(data)) {
            String[] pairs = data.split(",");
            for (String pair : pairs) {
                String[] keyValue = pair.split(":");
                if (keyValue.length == 2) {
                    String key = keyValue[0].trim();
                    String value = keyValue[1].trim();

                    switch (key) {
                        case "accessTokenTTL":
                            builder.accessTokenTimeToLive(Duration.ofSeconds(Long.parseLong(value)));
                            break;
                        case "refreshTokenTTL":
                            builder.refreshTokenTimeToLive(Duration.ofSeconds(Long.parseLong(value)));
                            break;
                        case "authorizationCodeTTL":
                            builder.authorizationCodeTimeToLive(Duration.ofSeconds(Long.parseLong(value)));
                            break;
                    }
                }
            }
        }

        return builder.build();
    }

    private ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.NONE;
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.CLIENT_SECRET_JWT;
        } else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue().equals(clientAuthenticationMethod)) {
            return ClientAuthenticationMethod.PRIVATE_KEY_JWT;
        }
        return new ClientAuthenticationMethod(clientAuthenticationMethod);
    }

    private AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        }
        return new AuthorizationGrantType(authorizationGrantType);
    }
}