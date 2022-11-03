package com.example.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    private final UserDetailsService userService;

    public AuthorizationServerConfig(AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, UserDetailsService userService) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("as466gf");
        return converter;
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer configurer) throws Exception {

        configurer
                .inMemory()

                .withClient("clientOne")
                .secret(passwordEncoder.encode("secretOne"))
                .authorizedGrantTypes("authorization_code")
                .autoApprove(false)
                .scopes("read", "write", "trust")
                .redirectUris("http://localhost:8484/api/login")
                .accessTokenValiditySeconds(6 * 60 * 60)
                .refreshTokenValiditySeconds(6 * 60 * 60)

                .and()

                .withClient("clientTwo")
                .secret(passwordEncoder.encode("secretTwo"))
                .authorizedGrantTypes("password")
                .scopes("openid")
                .accessTokenValiditySeconds(6 * 60 * 60)
                .refreshTokenValiditySeconds(6 * 60 * 60)

                .and()

                .withClient("clientThree")
                .secret(passwordEncoder.encode("secretThree"))
                .authorizedGrantTypes("client_credentials")
                .scopes("openid")
                .accessTokenValiditySeconds(6 * 60 * 60)
                .refreshTokenValiditySeconds(6 * 60 * 60);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.tokenStore(tokenStore())
                .userDetailsService(userService)
                .authenticationManager(authenticationManager)
                .accessTokenConverter(accessTokenConverter());
    }
}