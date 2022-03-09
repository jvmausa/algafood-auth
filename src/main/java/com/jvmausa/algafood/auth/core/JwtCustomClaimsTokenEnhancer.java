package com.jvmausa.algafood.auth.core;

import java.util.HashMap;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

public class JwtCustomClaimsTokenEnhancer implements TokenEnhancer {

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

		//se autenticacao for um resource server, não há nome_completo, então retorna o nome do resource
		//por isso uma validacao para identificar se é existe um usuario final(resource owner) na autenticacao
		if (authentication.getPrincipal() instanceof AuthUser) {
			var authUser = (AuthUser) authentication.getPrincipal();

			var info = new HashMap<String, Object>();
			info.put("nome_completo", authUser.getFullName());

			info.put("id_user", authUser.getUserId());

			var oAuth2Token = (DefaultOAuth2AccessToken) accessToken;
			oAuth2Token.setAdditionalInformation(info);

		}

		return accessToken;
	}

}
