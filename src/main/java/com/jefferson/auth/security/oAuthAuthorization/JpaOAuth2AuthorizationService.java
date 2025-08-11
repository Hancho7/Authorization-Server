package com.jefferson.auth.security.oAuthAuthorization;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

@Service
@Transactional
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationJpaRepository authorizationRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final ObjectMapper objectMapper;

    public JpaOAuth2AuthorizationService(
            OAuth2AuthorizationJpaRepository authorizationRepository,
            RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(authorizationRepository, "authorizationRepository cannot be null");
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.authorizationRepository = authorizationRepository;
        this.registeredClientRepository = registeredClientRepository;

        this.objectMapper = new ObjectMapper();
        this.objectMapper.findAndRegisterModules();
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        try {
            OAuth2AuthorizationEntity entity = toEntity(authorization);
            authorizationRepository.save(entity);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to save OAuth2Authorization: " + ex.getMessage(), ex);
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        authorizationRepository.deleteById(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return authorizationRepository.findById(id).map(this::toObject).orElse(null);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");

        Optional<OAuth2AuthorizationEntity> result;
        if (tokenType == null) {
            result = authorizationRepository.findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(token);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            result = authorizationRepository.findByState(token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            result = authorizationRepository.findByAuthorizationCodeValue(token);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            result = authorizationRepository.findByAccessTokenValue(token);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            result = authorizationRepository.findByRefreshTokenValue(token);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            result = authorizationRepository.findByOidcIdTokenValue(token);
        } else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
            result = authorizationRepository.findByUserCodeValue(token);
        } else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
            result = authorizationRepository.findByDeviceCodeValue(token);
        } else {
            result = Optional.empty();
        }

        return result.map(this::toObject).orElse(null);
    }

    private OAuth2AuthorizationEntity toEntity(OAuth2Authorization authorization) {
        OAuth2AuthorizationEntity entity = new OAuth2AuthorizationEntity();
        entity.setId(authorization.getId());
        entity.setRegisteredClientId(authorization.getRegisteredClientId());
        entity.setPrincipalName(authorization.getPrincipalName());
        entity.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
        entity.setAuthorizedScopes(StringUtils.collectionToCommaDelimitedString(authorization.getAuthorizedScopes()));

        // Store attributes including OAuth2AuthorizationRequest
        entity.setAttributes(writeAttributes(authorization.getAttributes()));
        entity.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        setTokenValues(authorizationCode, entity::setAuthorizationCodeValue,
                entity::setAuthorizationCodeIssuedAt, entity::setAuthorizationCodeExpiresAt,
                entity::setAuthorizationCodeMetadata);

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        setTokenValues(accessToken, entity::setAccessTokenValue,
                entity::setAccessTokenIssuedAt, entity::setAccessTokenExpiresAt,
                entity::setAccessTokenMetadata);
        if (accessToken != null && accessToken.getToken().getTokenType() != null) {
            entity.setAccessTokenType(accessToken.getToken().getTokenType().getValue());
        }
        if (accessToken != null && accessToken.getToken().getScopes() != null) {
            entity.setAccessTokenScopes(StringUtils.collectionToCommaDelimitedString(accessToken.getToken().getScopes()));
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        setTokenValues(refreshToken, entity::setRefreshTokenValue,
                entity::setRefreshTokenIssuedAt, entity::setRefreshTokenExpiresAt,
                entity::setRefreshTokenMetadata);

        OAuth2Authorization.Token<OidcIdToken> oidcIdToken =
                authorization.getToken(OidcIdToken.class);
        setTokenValues(oidcIdToken, entity::setOidcIdTokenValue,
                entity::setOidcIdTokenIssuedAt, entity::setOidcIdTokenExpiresAt,
                entity::setOidcIdTokenMetadata);

        OAuth2Authorization.Token<OAuth2UserCode> userCode =
                authorization.getToken(OAuth2UserCode.class);
        setTokenValues(userCode, entity::setUserCodeValue,
                entity::setUserCodeIssuedAt, entity::setUserCodeExpiresAt,
                entity::setUserCodeMetadata);

        OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode =
                authorization.getToken(OAuth2DeviceCode.class);
        setTokenValues(deviceCode, entity::setDeviceCodeValue,
                entity::setDeviceCodeIssuedAt, entity::setDeviceCodeExpiresAt,
                entity::setDeviceCodeMetadata);

        return entity;
    }

    private OAuth2Authorization toObject(OAuth2AuthorizationEntity entity) {
        try {
            RegisteredClient registeredClient = registeredClientRepository.findById(entity.getRegisteredClientId());
            if (registeredClient == null) {
                throw new IllegalArgumentException("Registered client not found with ID: " + entity.getRegisteredClientId());
            }

            OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
                    .id(entity.getId())
                    .principalName(entity.getPrincipalName())
                    .authorizationGrantType(resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))
                    .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()));

            // Parse all attributes including OAuth2AuthorizationRequest
            Map<String, Object> attributes = parseAttributes(entity.getAttributes());
            if (!attributes.isEmpty()) {
                builder.attributes(attrs -> attrs.putAll(attributes));
            }

            if (entity.getState() != null) {
                builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
            }

            if (entity.getAuthorizationCodeValue() != null) {
                OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                        entity.getAuthorizationCodeValue(), entity.getAuthorizationCodeIssuedAt(), entity.getAuthorizationCodeExpiresAt());
                Map<String, Object> metadata = parseSimpleAttributes(entity.getAuthorizationCodeMetadata());
                builder.token(authorizationCode, meta -> meta.putAll(metadata));
            }

            if (entity.getAccessTokenValue() != null) {
                OAuth2AccessToken accessToken = new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        entity.getAccessTokenValue(),
                        entity.getAccessTokenIssuedAt(),
                        entity.getAccessTokenExpiresAt(),
                        StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes()));
                Map<String, Object> metadata = parseSimpleAttributes(entity.getAccessTokenMetadata());
                builder.token(accessToken, meta -> meta.putAll(metadata));
            }

            if (entity.getRefreshTokenValue() != null) {
                OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                        entity.getRefreshTokenValue(), entity.getRefreshTokenIssuedAt(), entity.getRefreshTokenExpiresAt());
                Map<String, Object> metadata = parseSimpleAttributes(entity.getRefreshTokenMetadata());
                builder.token(refreshToken, meta -> meta.putAll(metadata));
            }

            if (entity.getOidcIdTokenValue() != null) {
                Map<String, Object> claims = parseSimpleAttributes(entity.getOidcIdTokenMetadata());
                OidcIdToken idToken = new OidcIdToken(
                        entity.getOidcIdTokenValue(), entity.getOidcIdTokenIssuedAt(), entity.getOidcIdTokenExpiresAt(), claims);
                builder.token(idToken, meta -> meta.putAll(claims));
            }

            if (entity.getUserCodeValue() != null) {
                OAuth2UserCode userCode = new OAuth2UserCode(
                        entity.getUserCodeValue(), entity.getUserCodeIssuedAt(), entity.getUserCodeExpiresAt());
                Map<String, Object> metadata = parseSimpleAttributes(entity.getUserCodeMetadata());
                builder.token(userCode, meta -> meta.putAll(metadata));
            }

            if (entity.getDeviceCodeValue() != null) {
                OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
                        entity.getDeviceCodeValue(), entity.getDeviceCodeIssuedAt(), entity.getDeviceCodeExpiresAt());
                Map<String, Object> metadata = parseSimpleAttributes(entity.getDeviceCodeMetadata());
                builder.token(deviceCode, meta -> meta.putAll(metadata));
            }

            return builder.build();
        } catch (Exception ex) {
            System.err.println("Failed to convert OAuth2AuthorizationEntity to OAuth2Authorization. Entity ID: " + entity.getId());
            System.err.println("Error details: " + ex.getMessage());
            throw new IllegalArgumentException("Failed to convert OAuth2AuthorizationEntity to OAuth2Authorization: " + ex.getMessage(), ex);
        }
    }

    private void setTokenValues(OAuth2Authorization.Token<?> token,
                                Consumer<String> tokenValueConsumer,
                                Consumer<Instant> issuedAtConsumer,
                                Consumer<Instant> expiresAtConsumer,
                                Consumer<String> metadataConsumer) {
        if (token != null) {
            OAuth2Token oAuth2Token = token.getToken();
            tokenValueConsumer.accept(oAuth2Token.getTokenValue());
            issuedAtConsumer.accept(oAuth2Token.getIssuedAt());
            expiresAtConsumer.accept(oAuth2Token.getExpiresAt());
            metadataConsumer.accept(writeSimpleMap(token.getMetadata()));
        }
    }

    private String writeAttributes(Map<String, Object> attributes) {
        try {
            Map<String, Object> serializableAttributes = new HashMap<>();

            for (Map.Entry<String, Object> entry : attributes.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();

                if (value instanceof String || value instanceof Number || value instanceof Boolean || value == null) {
                    serializableAttributes.put(key, value);
                } else if (value instanceof OAuth2AuthorizationRequest) {
                    // Serialize OAuth2AuthorizationRequest as a nested object
                    OAuth2AuthorizationRequest authRequest = (OAuth2AuthorizationRequest) value;
                    Map<String, Object> authRequestMap = new HashMap<>();
                    authRequestMap.put("authorizationUri", authRequest.getAuthorizationUri());
                    authRequestMap.put("clientId", authRequest.getClientId());
                    authRequestMap.put("redirectUri", authRequest.getRedirectUri());
                    authRequestMap.put("scopes", authRequest.getScopes());
                    authRequestMap.put("state", authRequest.getState());
                    authRequestMap.put("additionalParameters", authRequest.getAdditionalParameters());
                    authRequestMap.put("authorizationRequestUri", authRequest.getAuthorizationRequestUri());
                    authRequestMap.put("attributes", authRequest.getAttributes());

                    serializableAttributes.put(key, authRequestMap);
                } else if (key.equals(OAuth2ParameterNames.STATE)) {
                    // Always keep the state parameter
                    serializableAttributes.put(key, value != null ? value.toString() : null);
                }
                // Skip other complex objects
            }

            return objectMapper.writeValueAsString(serializableAttributes);
        } catch (Exception ex) {
            System.err.println("Failed to serialize attributes: " + ex.getMessage());
            return "{}";
        }
    }

    private String writeSimpleMap(Map<String, Object> data) {
        try {
            if (data == null || data.isEmpty()) {
                return "{}";
            }

            // Filter to only simple types
            Map<String, Object> simpleData = new HashMap<>();
            for (Map.Entry<String, Object> entry : data.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof String || value instanceof Number || value instanceof Boolean || value == null) {
                    simpleData.put(entry.getKey(), value);
                }
            }

            return objectMapper.writeValueAsString(simpleData);
        } catch (Exception ex) {
            System.err.println("Failed to serialize map: " + ex.getMessage());
            return "{}";
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseAttributes(String data) {
        try {
            if (!StringUtils.hasText(data) || data.equals("{}")) {
                return new HashMap<>();
            }

            Map<String, Object> rawAttributes = objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
            Map<String, Object> attributes = new HashMap<>();

            for (Map.Entry<String, Object> entry : rawAttributes.entrySet()) {
                String key = entry.getKey();
                Object value = entry.getValue();

                if (value instanceof Map && "org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest".equals(key)) {
                    // Reconstruct OAuth2AuthorizationRequest
                    Map<String, Object> authRequestMap = (Map<String, Object>) value;
                    OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest.authorizationCode()
                            .authorizationUri((String) authRequestMap.get("authorizationUri"))
                            .clientId((String) authRequestMap.get("clientId"))
                            .redirectUri((String) authRequestMap.get("redirectUri"))
                            .state((String) authRequestMap.get("state"));

                    if (authRequestMap.get("scopes") != null) {
                        Set<String> scopes = new HashSet<>((Collection<String>) authRequestMap.get("scopes"));
                        builder.scopes(scopes);
                    }

                    if (authRequestMap.get("additionalParameters") != null) {
                        Map<String, Object> additionalParams = (Map<String, Object>) authRequestMap.get("additionalParameters");
                        builder.additionalParameters(additionalParams);
                    }

                    if (authRequestMap.get("attributes") != null) {
                        Map<String, Object> requestAttributes = (Map<String, Object>) authRequestMap.get("attributes");
                        builder.attributes(attrs -> attrs.putAll(requestAttributes));
                    }

                    attributes.put(key, builder.build());
                } else {
                    attributes.put(key, value);
                }
            }

            return attributes;
        } catch (Exception ex) {
            System.err.println("Failed to parse attributes, using empty map. Error: " + ex.getMessage());
            return new HashMap<>();
        }
    }

    private Map<String, Object> parseSimpleAttributes(String data) {
        try {
            if (!StringUtils.hasText(data) || data.equals("{}")) {
                return new HashMap<>();
            }

            Map<String, Object> result = objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
            return result != null ? result : new HashMap<>();
        } catch (Exception ex) {
            System.err.println("Failed to parse attributes, using empty map. Error: " + ex.getMessage());
            return new HashMap<>();
        }
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