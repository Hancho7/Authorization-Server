package com.jefferson.auth.security.oAuthConsent;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Set;

@Service
@Transactional
public class JpaOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

    private final OAuth2AuthorizationConsentJpaRepository consentRepository;

    public JpaOAuth2AuthorizationConsentService(OAuth2AuthorizationConsentJpaRepository consentRepository) {
        this.consentRepository = consentRepository;
    }

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");

        OAuth2AuthorizationConsentEntity entity = toEntity(authorizationConsent);
        consentRepository.save(entity);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");

        consentRepository.deleteByRegisteredClientIdAndPrincipalName(
                authorizationConsent.getRegisteredClientId(),
                authorizationConsent.getPrincipalName());
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");

        return consentRepository.findByRegisteredClientIdAndPrincipalName(registeredClientId, principalName)
                .map(this::toObject).orElse(null);
    }

    private OAuth2AuthorizationConsentEntity toEntity(OAuth2AuthorizationConsent authorizationConsent) {
        String authorities = StringUtils.collectionToCommaDelimitedString(
                authorizationConsent.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
        );

        return new OAuth2AuthorizationConsentEntity(
                authorizationConsent.getRegisteredClientId(),
                authorizationConsent.getPrincipalName(),
                authorities
        );
    }

    private OAuth2AuthorizationConsent toObject(OAuth2AuthorizationConsentEntity entity) {
        String registeredClientId = entity.getRegisteredClientId();
        String principalName = entity.getPrincipalName();

        OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(registeredClientId, principalName);

        if (StringUtils.hasText(entity.getAuthorities())) {
            Set<String> authorities = StringUtils.commaDelimitedListToSet(entity.getAuthorities());
            builder.authorities(grantedAuthorities -> {
                for (String authority : authorities) {
                    grantedAuthorities.add(new SimpleGrantedAuthorityDeserializer(authority));
                }
            });
        }

        return builder.build();
    }

    private static class SimpleGrantedAuthorityDeserializer implements GrantedAuthority {
        private final String authority;

        SimpleGrantedAuthorityDeserializer(String authority) {
            this.authority = authority;
        }

        @Override
        public String getAuthority() {
            return this.authority;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof GrantedAuthority) {
                return authority.equals(((GrantedAuthority) obj).getAuthority());
            }
            return false;
        }

        @Override
        public int hashCode() {
            return authority.hashCode();
        }

        @Override
        public String toString() {
            return authority;
        }
    }
}