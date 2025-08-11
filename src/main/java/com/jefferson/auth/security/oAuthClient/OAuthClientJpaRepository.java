package com.jefferson.auth.security.oAuthClient;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OAuthClientJpaRepository extends JpaRepository<OAuthClientEntity, String> {
    OAuthClientEntity findByClientId(String clientId);
}