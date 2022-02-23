package com.jvmausa.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter{

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailService;
	
	/*COnfigurar os clients que podem acessar esse authorizationServer e depois vão acessar os recursos protegidos
		no resource server(aplicação)*/
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
		.inMemory()
			.withClient("algafood-web")
			.secret(passwordEncoder.encode("web123"))
			.authorizedGrantTypes("password", "refresh_token")
			.scopes("write", "read")
			.accessTokenValiditySeconds(15)
			.refreshTokenValiditySeconds(30)
		.and()
			.withClient("faturamento")
			.secret(passwordEncoder.encode("faturamento123"))
			.authorizedGrantTypes("client_credentials")
			.scopes("read")
		.and()
			.withClient("foodanalystics")
			.secret(passwordEncoder.encode("food123"))
			.authorizedGrantTypes("authorization_code")
			.scopes("write", "read")
			.redirectUris("http://aplicacao-cliente")
		.and()
			.withClient("checktoken")
			.secret(passwordEncoder.encode("checktoken123"));
		
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("permitAll()");
//		security.checkTokenAccess("isAuthenticated()");

	}
	
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailService)
			.reuseRefreshTokens(false);
	}
	
}
