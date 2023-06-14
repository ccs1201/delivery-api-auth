package com.example.deliveryapi.auth.core.configurations;

import com.example.deliveryapi.auth.PkceAuthorizationCodeTokenGranter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.util.Arrays;

@Configuration
@EnableAuthorizationServer
@RequiredArgsConstructor
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private static final String SECRET = "QS1zyuuDIHklis01*n15%PLVLaR64@Xj";
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtKeyProperties jwtKeyProperties;
//    private final RedisConnectionFactory redisConnectionFactory;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                .inMemory()
                .withClient("postman")
                .authorizedGrantTypes("password", "refresh_token")
                .secret(passwordEncoder.encode("postman123"))
                .scopes("read", "write")
                .accessTokenValiditySeconds(60 * 60 * 4) //4 Horas
                .refreshTokenValiditySeconds(60 * 60 * 12) //12 Horas
                .and()
                .withClient("resourceserver")
                .secret(passwordEncoder.encode("resourceserver321"))
                .and()
                .withClient("outraAplicacao")
                .secret(passwordEncoder.encode("outra123"))
                .authorizedGrantTypes("client_credentials")
                .scopes("read", "write")
                .and()
                .withClient("appAnalytics")
                .authorizedGrantTypes("authorization_code", "refresh_token")
                .secret(passwordEncoder.encode("appAnalytics123"))
                .scopes("read", "write")
                .redirectUris("http://analyticsapp")
                .and()
                .withClient("implicitGrantClient")
                .authorizedGrantTypes("implicit")
                .scopes("read", "write")
                .redirectUris("http://implicitGrantClient");

    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()")
                .tokenKeyAccess("permitAll()")
                .allowFormAuthenticationForClients();
//        security.checkTokenAccess("permitAll()");
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        var jwt = new JwtAccessTokenConverter();
//        jwt.setSigningKey(SECRET); para assinatura simétrica

        var jksResource = new ClassPathResource(jwtKeyProperties.getPath());

        var keyStoreFactory = new KeyStoreKeyFactory(jksResource, jwtKeyProperties.getPassword().toCharArray());
        var keyPair = keyStoreFactory.getKeyPair(jwtKeyProperties.getKeyPairAlias());

        jwt.setKeyPair(keyPair);

        return jwt;
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService)
                .reuseRefreshTokens(false)
//                .tokenStore(redisTokenStore())
                .accessTokenConverter(jwtAccessTokenConverter())
                .approvalStore(approvalStore(endpoints.getTokenStore()))
                .tokenGranter(tokenGranter(endpoints));
    }

    /**
     * <p>Habilita a aprovação granular de escopos com uso de JWT</p>
     * Módulo 23.13
     */
    private ApprovalStore approvalStore(TokenStore tokenStore) {

        var aprovalStore = new TokenApprovalStore();
        aprovalStore.setTokenStore(tokenStore);
        return aprovalStore;
    }

//    private TokenStore redisTokenStore(){
//        return new RedisTokenStore(redisConnectionFactory);
//    }

    private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
        var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
                endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory());

        var granters = Arrays.asList(
                pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

        return new CompositeTokenGranter(granters);
    }
}
