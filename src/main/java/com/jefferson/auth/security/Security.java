package com.jefferson.auth.security;

import com.jefferson.auth.config.JwtTokenCustomizer;
import com.jefferson.auth.security.oAuthAuthorization.JpaOAuth2AuthorizationService;
import com.jefferson.auth.security.oAuthClient.CustomRegisteredClientRepository;
import com.jefferson.auth.security.oAuthConsent.JpaOAuth2AuthorizationConsentService;
import com.jefferson.auth.users.CustomUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@Configuration
public class Security {

    private final CustomRegisteredClientRepository customRegisteredClientRepository;
    private final JpaOAuth2AuthorizationService authorizationService;
    private final JpaOAuth2AuthorizationConsentService authorizationConsentService;
    private final JwtTokenCustomizer jwtTokenCustomizer;
    private final CustomUserDetailsService customUserDetailsService;

    public Security(CustomRegisteredClientRepository customRegisteredClientRepository,
                    JpaOAuth2AuthorizationService authorizationService,
                    JpaOAuth2AuthorizationConsentService authorizationConsentService,
                    JwtTokenCustomizer jwtTokenCustomizer, CustomUserDetailsService customUserDetailsService) {
        this.customRegisteredClientRepository = customRegisteredClientRepository;
        this.authorizationService = authorizationService;
        this.authorizationConsentService = authorizationConsentService;
        this.jwtTokenCustomizer = jwtTokenCustomizer;
        this.customUserDetailsService = customUserDetailsService;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                .registeredClientRepository(customRegisteredClientRepository)
                                .authorizationService(authorizationService)
                                .authorizationConsentService(authorizationConsentService)
                                .authorizationServerSettings(authorizationServerSettings())
                                .tokenGenerator(tokenGenerator())
                                .oidc(oidc -> oidc
                                        .providerConfigurationEndpoint(Customizer.withDefaults())
                                        .logoutEndpoint(Customizer.withDefaults())
                                        .userInfoEndpoint(Customizer.withDefaults())
                                        .clientRegistrationEndpoint(Customizer.withDefaults())
                                )
                )
                .authorizeHttpRequests((authorize) ->
                        authorize
                                .anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {

        // Custom success handler that preserves the original OAuth2 flow
        SavedRequestAwareAuthenticationSuccessHandler successHandler =
                new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/");
        successHandler.setAlwaysUseDefaultTargetUrl(false);

        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/admin/oauth-clients/**").hasRole("ADMIN")
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        .requestMatchers("/actuator/**").hasRole("ADMIN")
                        .requestMatchers("/error", "/logout-success").permitAll()
                        .requestMatchers("/login", "/oauth2/**", "/").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/oauth2/**")
                        .disable()
                )
                .httpBasic(Customizer.withDefaults())
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(successHandler)
                        .failureUrl("/login?error")
                        .permitAll()
                )
                .userDetailsService(customUserDetailsService)
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/logout-success")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                .sessionManagement(session -> session
                        .maximumSessions(10)
                        .maxSessionsPreventsLogin(false)
                        .sessionRegistry(sessionRegistry())
                )
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.deny())
                        .contentTypeOptions(Customizer.withDefaults())
                        .httpStrictTransportSecurity(hsts -> hsts
                                .maxAgeInSeconds(31536000)
                                .includeSubDomains(true)
                        )
                );

        return http.build();
    }


    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public OAuth2TokenGenerator<?> tokenGenerator() {
        try {
            JWKSource<SecurityContext> jwkSource = jwkSource();
            NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);

            JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
            if (jwtTokenCustomizer != null) {
                jwtGenerator.setJwtCustomizer(jwtTokenCustomizer);
            }

            OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
            OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

            return new DelegatingOAuth2TokenGenerator(
                    jwtGenerator, accessTokenGenerator, refreshTokenGenerator);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to create token generator: " + e.getMessage(), e);
        }
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            if (keyPair.getPrivate() == null || keyPair.getPublic() == null) {
                throw new IllegalStateException("Generated key pair is incomplete");
            }

            return keyPair;
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate RSA key pair: " + ex.getMessage(), ex);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8080")
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public org.springframework.security.core.session.SessionRegistry sessionRegistry() {
        return new org.springframework.security.core.session.SessionRegistryImpl();
    }
}