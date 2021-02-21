package com.algaworks.algafood.auth.core;

import java.util.HashMap;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

@SuppressWarnings("deprecation")
public class JwtCustomClaimsTokenEnhancer implements TokenEnhancer {

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		var novoAccessToken = (DefaultOAuth2AccessToken) accessToken;		
		if (authentication.getPrincipal() instanceof AuthUser) {
	//		Instanciamento de um objeto de usuário, a partir do authentication
			AuthUser authUser = (AuthUser) authentication.getPrincipal();
	//		Criação dos claims adicionais que desejamos incluir no payload do JWT
			var info = new HashMap<String, Object>();
			info.put("user_id", authUser.getUserId());
			info.put("nome_completo", authUser.getFullName());
	//		Inclusão dos claims customizados no accessToken
			novoAccessToken.setAdditionalInformation(info);
		}
		return novoAccessToken;
	}
	
}
