package com.example.authorizationserver.config;

import com.example.authorizationserver.filter.CustomAccessDeniedHandler;
import com.example.authorizationserver.filter.CustomAuthenticationEntryPoint;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

	private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

	public ResourceServerConfig(CustomAuthenticationEntryPoint customAuthenticationEntryPoint) {
		this.customAuthenticationEntryPoint = customAuthenticationEntryPoint;
	}

	@Override
	public void configure(ResourceServerSecurityConfigurer resources) {
		resources.resourceId("user").stateless(false);
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.antMatcher("/user")
				.authorizeRequests()
				.anyRequest().authenticated()
				.and()
				.exceptionHandling().authenticationEntryPoint(customAuthenticationEntryPoint).accessDeniedHandler(new CustomAccessDeniedHandler());
	}

}