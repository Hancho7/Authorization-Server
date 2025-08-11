package com.jefferson.auth.security.oAuthConsent;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2AuthorizationConsentJpaRepository extends JpaRepository<OAuth2AuthorizationConsentEntity, OAuth2AuthorizationConsentEntity.AuthorizationConsentId> {

    Optional<OAuth2AuthorizationConsentEntity> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);

    @Modifying
    @Query("DELETE FROM OAuth2AuthorizationConsentEntity ac WHERE ac.registeredClientId = :registeredClientId AND ac.principalName = :principalName")
    void deleteByRegisteredClientIdAndPrincipalName(@Param("registeredClientId") String registeredClientId, @Param("principalName") String principalName);
}