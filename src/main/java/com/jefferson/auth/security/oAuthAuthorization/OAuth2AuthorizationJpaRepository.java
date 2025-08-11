package com.jefferson.auth.security.oAuthAuthorization;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuth2AuthorizationJpaRepository extends JpaRepository<OAuth2AuthorizationEntity, String> {

    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE a.state = :token OR " +
            "a.authorizationCodeValue = :token OR " +
            "a.accessTokenValue = :token OR " +
            "a.refreshTokenValue = :token OR " +
            "a.oidcIdTokenValue = :token OR " +
            "a.userCodeValue = :token OR " +
            "a.deviceCodeValue = :token")
    Optional<OAuth2AuthorizationEntity> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(@Param("token") String token);

    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE a.state = :state")
    Optional<OAuth2AuthorizationEntity> findByState(@Param("state") String state);

    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE a.authorizationCodeValue = :authorizationCode")
    Optional<OAuth2AuthorizationEntity> findByAuthorizationCodeValue(@Param("authorizationCode") String authorizationCode);

    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE a.accessTokenValue = :accessToken")
    Optional<OAuth2AuthorizationEntity> findByAccessTokenValue(@Param("accessToken") String accessToken);

    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE a.refreshTokenValue = :refreshToken")
    Optional<OAuth2AuthorizationEntity> findByRefreshTokenValue(@Param("refreshToken") String refreshToken);

    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE a.oidcIdTokenValue = :idToken")
    Optional<OAuth2AuthorizationEntity> findByOidcIdTokenValue(@Param("idToken") String idToken);

    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE a.userCodeValue = :userCode")
    Optional<OAuth2AuthorizationEntity> findByUserCodeValue(@Param("userCode") String userCode);

    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE a.deviceCodeValue = :deviceCode")
    Optional<OAuth2AuthorizationEntity> findByDeviceCodeValue(@Param("deviceCode") String deviceCode);
}