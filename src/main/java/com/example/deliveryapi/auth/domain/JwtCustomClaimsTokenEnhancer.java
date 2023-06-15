package com.example.deliveryapi.auth.domain;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;

/**
 * Customiza a representação do token JWT
 */
public class JwtCustomClaimsTokenEnhancer implements TokenEnhancer {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

        if (authentication.getPrincipal() instanceof AuthUser) {

            var authUser = (AuthUser) authentication.getPrincipal();

            var informacoesAdicionais = new HashMap<String, Object>();
            informacoesAdicionais.put("nome_completo", authUser.getNomeCompleto());
            informacoesAdicionais.put("usuario_id", authUser.getUserId());

            var oAuth2AccessToken = (DefaultOAuth2AccessToken) accessToken;
            oAuth2AccessToken.setAdditionalInformation(informacoesAdicionais);
        }

        return accessToken;
    }
}
