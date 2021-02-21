package com.algaworks.algafood.auth.core;

import java.security.KeyPair;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@SuppressWarnings("deprecation")
@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("algafood-web")
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("READ", "WRITE")
				.accessTokenValiditySeconds(3600*6)  // 6 horas
				.refreshTokenValiditySeconds(3600*24*15) // 15 dias
			.and()
				.withClient("algafood-batch")
				.secret(passwordEncoder.encode("batch123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("READ")
			.and()
				.withClient("algafood-analytics")
				.secret(passwordEncoder.encode("ana123"))
				.authorizedGrantTypes("authorization_code")
				.scopes("READ")
//				URL de callback
				.redirectUris("http://www.foodanalytics.local:8082")
			.and()
				.withClient("webadmin")
				.authorizedGrantTypes("implicit")
				.scopes("READ", "WRITE")
//				URL de callback
				.redirectUris("http://url_da_aplicacao")
			.and()
				.withClient("algafood-api")
				.secret(passwordEncoder.encode("api123"))
				.authorizedGrantTypes("password", "outrofluxo")
				.scopes("READ", "WRITE");
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		A requisição para consulta do token deve, obrigatoriamente, 
//		conter as credenciais de acesso do App Client
		security.checkTokenAccess("isAuthenticated()");
		
//		A requisição para consulta do token não precisa conter
//		as credenciais de acesso do App Client
//		security.checkTokenAccess("permitAll()");
		
//		Permite todos os acessos no endpoint tokenKey
		security.tokenKeyAccess("permitAll()");
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//		Lista de Token Enhancers a serem incluídos na geração do token JWT
		var enhancerChain = new TokenEnhancerChain();
		enhancerChain.setTokenEnhancers(Arrays.asList(new JwtCustomClaimsTokenEnhancer(), jwtAccessTokenConverter()));
		
		endpoints.authenticationManager(authenticationManager);
		endpoints.userDetailsService(userDetailsService);
		endpoints.reuseRefreshTokens(false);
		endpoints.tokenGranter(tokenGranter(endpoints));
		endpoints.accessTokenConverter(jwtAccessTokenConverter());
		endpoints.approvalStore(approvalStore(endpoints.getTokenStore()));
		endpoints.tokenEnhancer(enhancerChain);
	}
	
	private ApprovalStore approvalStore(TokenStore tokenStore) {
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		return approvalStore;
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
//		Guardar a 7 chaves e utilizar senha complexa (melhor guardar no application.properties)
//		Método utilizado para gerar os JWTs com chave simétrica
//		jwtAccessTokenConverter.setSigningKey("algaworksalgaworksalgaworksalgaworks");

//		Informações para acesso ao arquivo jks com o par de chaves
		ClassPathResource jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
		String keyStorePass = jwtKeyStoreProperties.getPassword();
		String keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
//		Extração do keypair a partir do keystore (jks)
		KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
		KeyPair keypair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
		jwtAccessTokenConverter.setKeyPair(keypair);		
		
		return jwtAccessTokenConverter;		
	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}

}
