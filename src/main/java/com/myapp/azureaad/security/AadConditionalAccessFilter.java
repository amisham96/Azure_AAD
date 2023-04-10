package com.myapp.azureaad.security;


import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import com.azure.spring.cloud.autoconfigure.aad.AadClientRegistrationRepository;

public class AadConditionalAccessFilter extends OncePerRequestFilter {

    /**
     * Bearer prefix
     */
    private static final String BEARER_PREFIX = "Bearer "; // Whitespace at the end is necessary.

    /**
     * Conditional access policy claims
     */
    private static final String CONDITIONAL_ACCESS_POLICY_CLAIMS = "CONDITIONAL_ACCESS_POLICY_CLAIMS";

    /**
     * Do filter.
     *
     * @param request the HttpServletRequest
     * @param response the HttpServletResponse
     * @param filterChain the FilterChain
     * @throws IOException if an I/O related error has occurred during the processing
     * @throws ServletException if an exception has occurred that interferes with the
     *                          filterChain's normal operation
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws IOException, ServletException {
        // Handle conditional access policy, step 2.
        try {
            filterChain.doFilter(request, response);
        } catch (Exception exception) {
            Map<String, String> authParameters =
                Optional.of(exception)
                        .map(Throwable::getCause)
                        .filter(e -> e instanceof WebClientResponseException)
                        .map(e -> (WebClientResponseException) e)
                        .map(WebClientResponseException::getHeaders)
                        .map(httpHeaders -> httpHeaders.get(HttpHeaders.WWW_AUTHENTICATE))
                        .map(list -> list.get(0))
                        .map(this::parseAuthParameters)
                        .orElse(null);
            if (authParameters != null && authParameters.containsKey(CONDITIONAL_ACCESS_POLICY_CLAIMS)) {
                request.getSession().setAttribute(CONDITIONAL_ACCESS_POLICY_CLAIMS,
                    authParameters.get(CONDITIONAL_ACCESS_POLICY_CLAIMS));
                // OAuth2AuthorizationRequestRedirectFilter will catch this exception to re-authorize.
                throw new ClientAuthorizationRequiredException(AadClientRegistrationRepository.AZURE_CLIENT_REGISTRATION_ID);
            }
            throw exception;
        }
    }

    /**
     * Get claims filed form the header to re-authorize.
     *
     * @param wwwAuthenticateHeader httpHeader
     * @return authParametersMap
     */
    private Map<String, String> parseAuthParameters(String wwwAuthenticateHeader) {
        return Stream.of(wwwAuthenticateHeader)
                     .filter(StringUtils::hasText)
                     .filter(header -> header.startsWith(BEARER_PREFIX))
                     .map(str -> str.substring(BEARER_PREFIX.length() + 1, str.length() - 1))
                     .map(str -> str.split(", "))
                     .flatMap(Stream::of)
                     .map(parameter -> parameter.split("="))
                     .filter(parameter -> parameter.length > 1)
                     .collect(Collectors.toMap(
                         parameters -> parameters[0],
                         parameters -> parameters[1]));
    }
}
