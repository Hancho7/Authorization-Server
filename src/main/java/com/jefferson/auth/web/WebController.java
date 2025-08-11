package com.jefferson.auth.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@Controller
public class WebController {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationConsentService authorizationConsentService;
    private final OAuth2AuthorizationService authorizationService;

    public WebController(RegisteredClientRepository registeredClientRepository,
                         OAuth2AuthorizationConsentService authorizationConsentService,
                         OAuth2AuthorizationService authorizationService) {
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationConsentService = authorizationConsentService;
        this.authorizationService = authorizationService;
    }

    @GetMapping("/")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> home() {
        Map<String, Object> response = new HashMap<>();
        response.put("server", "OAuth2 Authorization Server");
        response.put("developer", "Jefferson Hancho");
        response.put("status", "running");
        response.put("version", "1.0.0");
        response.put("timestamp", new Date());

        Map<String, String> endpoints = new HashMap<>();
        endpoints.put("authorization", "/oauth2/authorize");
        endpoints.put("token", "/oauth2/token");
        endpoints.put("jwks", "/oauth2/jwks");
        endpoints.put("userInfo", "/userinfo");
        endpoints.put("openidConfiguration", "/.well-known/openid_configuration");
        response.put("endpoints", endpoints);

        return ResponseEntity.ok(response);
    }

    @GetMapping("/login")
    public String login(Model model,
                        @RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "logout", required = false) String logout,
                        HttpServletRequest request) {

        if (error != null) {
            model.addAttribute("error", "Invalid username or password!");
        }

        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully.");
        }

        // Store the original request parameters for post-login redirect
        String continueParam = request.getParameter("continue");
        if (continueParam != null) {
            model.addAttribute("continue", continueParam);
        }

        return "login";
    }

    @GetMapping(value = "/oauth2/consent")
    public String consent(Principal principal, Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(value = OAuth2ParameterNames.SCOPE, required = false) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state,
                          @RequestParam(name = OAuth2ParameterNames.USER_CODE, required = false) String userCode,
                          HttpServletRequest request) {

        // Validate client exists
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new RuntimeException("Client not found: " + clientId);
        }

        // Process scopes - handle empty/null scope parameter
        Set<String> requestedScopes = new HashSet<>();
        if (StringUtils.hasText(scope)) {
            String[] scopeArray = StringUtils.delimitedListToStringArray(scope, " ");
            requestedScopes.addAll(Arrays.asList(scopeArray));
        }

        Set<String> scopesToApprove = new HashSet<>();
        Set<String> previouslyApprovedScopes = new HashSet<>();

        // Get existing consent
        OAuth2AuthorizationConsent currentAuthorizationConsent =
                this.authorizationConsentService.findById(registeredClient.getId(), principal.getName());

        Set<String> authorizedScopes = currentAuthorizationConsent != null ?
                currentAuthorizationConsent.getScopes() : Collections.emptySet();

        // Categorize scopes
        for (String requestedScope : requestedScopes) {
            if (authorizedScopes.contains(requestedScope)) {
                previouslyApprovedScopes.add(requestedScope);
            } else {
                scopesToApprove.add(requestedScope);
            }
        }

        // Add all request parameters to model for form processing
        Map<String, String> requestParameters = new HashMap<>();
        request.getParameterMap().forEach((key, values) -> {
            if (values != null && values.length > 0) {
                requestParameters.put(key, values[0]);
            }
        });

        // Model attributes
        model.addAttribute("clientId", clientId);
        model.addAttribute("clientName", registeredClient.getClientName());
        model.addAttribute("state", state);
        model.addAttribute("scopes", withDescription(scopesToApprove));
        model.addAttribute("previouslyApprovedScopes", withDescription(previouslyApprovedScopes));
        model.addAttribute("principalName", principal.getName());
        model.addAttribute("userCode", userCode);
        model.addAttribute("requestParameters", requestParameters);

        // Determine the correct form action
        if (StringUtils.hasText(userCode)) {
            model.addAttribute("requestURI", "/oauth2/device_verification");
        } else {
            model.addAttribute("requestURI", "/oauth2/consent");
        }

        return "consent";
    }

    @PostMapping("/oauth2/consent")
    public RedirectView approveConsent(Principal principal,
                                       @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                                       @RequestParam(OAuth2ParameterNames.STATE) String state,
                                       @RequestParam(name = "scopes", required = false) Set<String> approvedScopes,
                                       @RequestParam(name = "action", defaultValue = "approve") String action,
                                       HttpServletRequest request) {

        // Handle denial
        if (!"approve".equals(action)) {
            return handleConsentDenial(request, state);
        }

        // Ensure scopes is not null
        if (approvedScopes == null) {
            approvedScopes = Collections.emptySet();
        }

        // Validate client
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw new RuntimeException("Client not found: " + clientId);
        }

        // Save consent with all scopes (existing + newly approved)
        saveConsentWithScopes(registeredClient, principal.getName(), approvedScopes);

        // Build redirect URL to continue OAuth flow
        return buildOAuthRedirect(clientId, state, approvedScopes, request);
    }

    @GetMapping("/error")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> error(HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        response.put("error", "An error occurred");
        response.put("timestamp", new Date());
        response.put("path", request.getRequestURI());

        Integer status = (Integer) request.getAttribute("javax.servlet.error.status_code");
        if (status != null) {
            response.put("status", status);
        }

        return ResponseEntity.status(status != null ? status : 500).body(response);
    }

    @GetMapping("/logout-success")
    public String logoutSuccess() {
        return "redirect:/login?logout";
    }

    // Helper methods

    private RedirectView handleConsentDenial(HttpServletRequest request, String state) {
        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);
        if (StringUtils.hasText(redirectUri)) {
            try {
                String errorUrl = redirectUri +
                        (redirectUri.contains("?") ? "&" : "?") +
                        "error=access_denied&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
                return new RedirectView(errorUrl);
            } catch (Exception e) {
                // Log the error and fallback to login page
                System.err.println("Error building denial redirect: " + e.getMessage());
            }
        }
        return new RedirectView("/login?error=consent_denied");
    }

    private void saveConsentWithScopes(RegisteredClient registeredClient, String principalName, Set<String> newScopes) {
        // Get existing consent
        OAuth2AuthorizationConsent existingConsent =
                this.authorizationConsentService.findById(registeredClient.getId(), principalName);

        // Build new consent with all scopes (existing + new)
        OAuth2AuthorizationConsent.Builder consentBuilder =
                OAuth2AuthorizationConsent.withId(registeredClient.getId(), principalName);

        Set<String> allScopes = new HashSet<>();

        // Add existing scopes (extract from authorities using the getScopes() convenience method)
        if (existingConsent != null) {
            allScopes.addAll(existingConsent.getScopes());
        }

        // Add newly approved scopes
        allScopes.addAll(newScopes);

        // Convert scopes to authorities using the proper OAuth2 format (SCOPE_ prefix)
        consentBuilder.authorities(authorities -> {
            for (String scope : allScopes) {
                authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
            }
        });

        OAuth2AuthorizationConsent authorizationConsent = consentBuilder.build();
        this.authorizationConsentService.save(authorizationConsent);
    }

    private RedirectView buildOAuthRedirect(String clientId, String state, Set<String> approvedScopes, HttpServletRequest request) {
        try {
            StringBuilder redirectUrl = new StringBuilder("/oauth2/authorize");
            redirectUrl.append("?client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8));
            redirectUrl.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));

            // Add essential OAuth2 REQUEST parameters (NOT response parameters like 'code')
            String[] parameterNames = {
                    OAuth2ParameterNames.RESPONSE_TYPE,        // e.g., "code"
                    OAuth2ParameterNames.REDIRECT_URI,         // client's redirect URI
                    OAuth2ParameterNames.SCOPE,                // requested scopes
                    OAuth2ParameterNames.STATE,                // state parameter
                    OAuth2ParameterNames.CLIENT_ID,            // client identifier
                    OAuth2ParameterNames.CODE         // e.g., "form_post"
            };

            for (String paramName : parameterNames) {
                String paramValue = request.getParameter(paramName);
                if (StringUtils.hasText(paramValue)) {
                    redirectUrl.append("&").append(paramName).append("=")
                            .append(URLEncoder.encode(paramValue, StandardCharsets.UTF_8));
                }
            }

            // Use approved scopes instead of original scope parameter
            if (!approvedScopes.isEmpty()) {
                String scopeString = String.join(" ", approvedScopes);
                redirectUrl.append("&scope=").append(URLEncoder.encode(scopeString, StandardCharsets.UTF_8));
            }

            return new RedirectView(redirectUrl.toString());
        } catch (Exception e) {
            throw new RuntimeException("Error building OAuth redirect", e);
        }
    }

    private static Set<ScopeWithDescription> withDescription(Set<String> scopes) {
        return scopes.stream()
                .map(ScopeWithDescription::new)
                .collect(Collectors.toSet());
    }

    public static class ScopeWithDescription {
        public final String scope;
        public final String description;

        ScopeWithDescription(String scope) {
            this.scope = scope;
            this.description = scopeDescriptions.getOrDefault(scope,
                    "Access to " + scope.replace("_", " ").toLowerCase() + " resources");
        }

        public String getScope() {
            return scope;
        }

        public String getDescription() {
            return description;
        }

        private static final Map<String, String> scopeDescriptions = Map.of(
                "openid", "Verify your identity using OpenID Connect",
                "profile", "Access your basic profile information (name, picture, etc.)",
                "email", "Access your email address",
                "address", "Access your address information",
                "phone", "Access your phone number",
                "offline_access", "Maintain access when you're not actively using the application",
                "read", "Read access to your data and resources",
                "write", "Ability to create and modify your data",
                "admin", "Administrative access to manage system settings"
        );
    }
}