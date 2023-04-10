package com.myapp.azureaad.security;

import javax.servlet.Filter;

import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import com.azure.spring.cloud.autoconfigure.aad.AadWebSecurityConfigurerAdapter;

@Profile("conditional-access")
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AadWebApplicationConfig extends AadWebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		super.configure(http);
		// @formatter:off
        http.authorizeRequests()
            .antMatchers("/login").permitAll()
            .anyRequest().authenticated();
        // @formatter:on
	}

	/**
	 * This method is only used for AAD conditional access support and can be
	 * removed if this feature is not used. {@inheritDoc}
	 * 
	 * @return the conditional access filter
	 */
	@Override
	protected Filter conditionalAccessFilter() {
		return new AadConditionalAccessFilter();
	}
}
