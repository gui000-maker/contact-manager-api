package com.example.contactmanager.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Spring Security configuration for the Contact Manager REST API.
 *
 * <p>Security model:</p>
 * <ul>
 *   <li>Stateless JWT authentication — no sessions or cookies</li>
 *   <li>CSRF disabled — not needed for stateless token-based APIs</li>
 *   <li>Passwords hashed with BCrypt</li>
 *   <li>Method-level security enabled via {@literal @}PreAuthorize</li>
 * </ul>
 *
 * <p>Public endpoints: /api/auth/**, /swagger-ui/**, /v3/api-docs/**</p>
 * <p>Admin only: /users/**</p>
 * <p>Everything else requires a valid JWT token.</p>
 */
@EnableMethodSecurity
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final ErrorResponseWriter errorResponseWriter;

    public SecurityConfig(ErrorResponseWriter errorResponseWriter) {
        this.errorResponseWriter = errorResponseWriter;
    }

    /**
     * Configures the main security filter chain.
     *
     * <p>Key decisions:</p>
     * <ul>
     *   <li>CSRF disabled: API is stateless, JWT is sent via Authorization header,
     *       not cookies — so CSRF attacks are not applicable</li>
     *   <li>Sessions stateless: no HttpSession is created or used between requests</li>
     *   <li>401 response: returned when no valid JWT is present</li>
     *   <li>403 response: returned when JWT is valid but role is insufficient</li>
     * </ul>
     *
     * <p>Filter order: {@link RateLimitFilter} runs before
     * {@link JwtAuthenticationFilter} to limit login attempts,
     * and {@link JwtAuthenticationFilter} runs before
     * {@link UsernamePasswordAuthenticationFilter} to validate the token
     * and populate the SecurityContext early in the chain.</p>
     *
     * @param http                   the HttpSecurity builder
     * @param jwtAuthenticationFilter the JWT filter injected as a bean
     * @param rateLimitFilter        the rate limit filter injected as a bean
     * @return the configured {@link SecurityFilterChain}
     * @throws Exception if security configuration fails
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   JwtAuthenticationFilter jwtAuthenticationFilter,
                                                   RateLimitFilter rateLimitFilter) throws Exception {

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, exAuth) ->
                                errorResponseWriter.write(
                                        response,
                                        HttpStatus.UNAUTHORIZED,
                                        "Unauthorized",
                                        request.getRequestURI()
                                )
                        )
                        .accessDeniedHandler((request, response, exDenied) ->
                                errorResponseWriter.write(
                                        response,
                                        HttpStatus.FORBIDDEN,
                                        "Access denied",
                                        request.getRequestURI()
                                )
                        )
                )

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/users/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )

                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Exposes the {@link AuthenticationManager} as a bean so it can be
     * injected into the auth service to manually authenticate
     * username/password during login.
     *
     * @param configuration Spring's authentication configuration
     * @return the application's {@link AuthenticationManager}
     * @throws Exception if the manager cannot be retrieved
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration
    ) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /**
     * Password encoder using BCrypt hashing algorithm.
     * BCrypt automatically handles salting, making it resistant
     * to rainbow table attacks.
     *
     * @return a {@link BCryptPasswordEncoder} instance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Registers the JWT authentication filter as a Spring bean.
     * Declared here to avoid circular dependency issues that arise
     * when the filter is annotated with {@literal @}Component directly.
     *
     * @param jwtService         handles token parsing and validation
     * @param userDetailsService loads user details from the database
     * @return a configured {@link JwtAuthenticationFilter}
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            JwtService jwtService,
            UserDetailsService userDetailsService
    ) {
        return new JwtAuthenticationFilter(jwtService, userDetailsService);
    }

    /**
     * CORS configuration to allow requests from the frontend application.
     *
     * <p>In production, this should be restricted to the specific origin(s)
     * of your frontend app for better security.</p>
     *
     * @return a {@link CorsConfigurationSource} with permissive settings
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(
                "http://localhost:5500",
                "http://127.0.0.1:5500"
        ));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
