package com.jefferson.auth.security.oAuthConsent;

import jakarta.persistence.*;
import java.util.Objects;

@Entity
@Table(name = "oauth_authorization_consent")
@IdClass(OAuth2AuthorizationConsentEntity.AuthorizationConsentId.class)
public class OAuth2AuthorizationConsentEntity {

    @Id
    @Column(name = "registered_client_id")
    private String registeredClientId;

    @Id
    @Column(name = "principal_name")
    private String principalName;

    @Column(name = "authorities", columnDefinition = "TEXT")
    private String authorities;

    // Constructors
    public OAuth2AuthorizationConsentEntity() {}

    public OAuth2AuthorizationConsentEntity(String registeredClientId, String principalName, String authorities) {
        this.registeredClientId = registeredClientId;
        this.principalName = principalName;
        this.authorities = authorities;
    }

    // Getters and Setters
    public String getRegisteredClientId() {
        return registeredClientId;
    }

    public void setRegisteredClientId(String registeredClientId) {
        this.registeredClientId = registeredClientId;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    public String getAuthorities() {
        return authorities;
    }

    public void setAuthorities(String authorities) {
        this.authorities = authorities;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OAuth2AuthorizationConsentEntity that = (OAuth2AuthorizationConsentEntity) o;
        return Objects.equals(registeredClientId, that.registeredClientId) &&
                Objects.equals(principalName, that.principalName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(registeredClientId, principalName);
    }

    // Composite Key Class
    public static class AuthorizationConsentId implements java.io.Serializable {
        private String registeredClientId;
        private String principalName;

        public AuthorizationConsentId() {}

        public AuthorizationConsentId(String registeredClientId, String principalName) {
            this.registeredClientId = registeredClientId;
            this.principalName = principalName;
        }

        public String getRegisteredClientId() {
            return registeredClientId;
        }

        public void setRegisteredClientId(String registeredClientId) {
            this.registeredClientId = registeredClientId;
        }

        public String getPrincipalName() {
            return principalName;
        }

        public void setPrincipalName(String principalName) {
            this.principalName = principalName;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            AuthorizationConsentId that = (AuthorizationConsentId) o;
            return Objects.equals(registeredClientId, that.registeredClientId) &&
                    Objects.equals(principalName, that.principalName);
        }

        @Override
        public int hashCode() {
            return Objects.hash(registeredClientId, principalName);
        }
    }
}

