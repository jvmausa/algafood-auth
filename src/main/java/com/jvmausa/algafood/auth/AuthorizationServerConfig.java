package com.jvmausa.algafood.auth;

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
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserDetailsService userDetailService;

	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties;

	/*
	 * COnfigurar os clients que podem acessar esse authorizationServer e depois vão
	 * acessar os recursos protegidos no resource server(aplicação)
	 */

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		
		clients
			.inMemory()
			.withClient("algafood-web")
			.secret(passwordEncoder.encode("web123"))
			.authorizedGrantTypes("password", "refresh_token")
			.scopes("write", "read")
//			.accessTokenValiditySeconds(300)
//			.refreshTokenValiditySeconds(600)
		.and()
			.withClient("faturamento")
			.secret(passwordEncoder.encode("faturamento123"))
			.authorizedGrantTypes("client_credentials")
			.scopes("read").and().withClient("foodanalytics")
			.secret(passwordEncoder.encode("food123"))
			.authorizedGrantTypes("authorization_code")
			.scopes("write", "read")
			.redirectUris("http://aplicacao-cliente")
//		.and() *nao recomendado*
//			.withClient("webadmin") 
//		    .authorizedGrantTypes("implicit")
//			.scopes("write", "read") .redirectUris("http://aplicacao-cliente") 
		.and()
			.withClient("checktoken")
			.secret(passwordEncoder.encode("checktoken123"));

	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("permitAll()")
		.tokenKeyAccess("permitAll()")
		.allowFormAuthenticationForClients();
//		security.checkTokenAccess("isAuthenticated()");

	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailService)
			.reuseRefreshTokens(false)
			.accessTokenConverter(jwtAccessTokenConverter())
			.approvalStore(approvalStore(endpoints.getTokenStore()))
			.tokenGranter(tokenGranter(endpoints));
	}

	private ApprovalStore approvalStore(TokenStore tokenStore) {
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		
		
		return null;
	}
	
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		var jwtAccessTokenConverter = new JwtAccessTokenConverter();

		var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
		var keyStorePass = jwtKeyStoreProperties.getPassword();
		var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();

		var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
		var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);

		jwtAccessTokenConverter.setKeyPair(keyPair);

		return jwtAccessTokenConverter;
	}

	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());

		var granters = Arrays.asList(pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());

		return new CompositeTokenGranter(granters);
	}

}
