package com.smart.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class MyConfig {
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public UserDetailsService getUserDetailsService() {
		return new UserDetailsServiceImpl();
	}
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf().disable().authorizeRequests().requestMatchers("/user/**").hasAuthority("ROLE_USER")
				.requestMatchers("/admin/**").hasAuthority("ADMIN").requestMatchers("/**").permitAll().anyRequest()
				.authenticated().and().formLogin().loginPage("/signin").defaultSuccessUrl("/user/index");
		return httpSecurity.build();
	}

}

/*
 * import org.springframework.boot.autoconfigure.security.servlet.
 * SecurityFilterAutoConfiguration; import
 * org.springframework.context.annotation.Bean; import
 * org.springframework.context.annotation.Configuration; import
 * org.springframework.security.authentication.dao.DaoAuthenticationProvider;
 * import
 * org.springframework.security.config.annotation.authentication.builders.
 * AuthenticationManagerBuilder; import
 * org.springframework.security.config.annotation.web.builders.HttpSecurity;
 * import org.springframework.security.config.annotation.web.configuration.
 * EnableWebSecurity; import
 * org.springframework.security.config.annotation.web.configuration.
 * WebSecurityConfiguration; import
 * org.springframework.security.core.userdetails.UserDetailsService; import
 * org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; import
 * org.springframework.security.web.SecurityFilterChain;
 * 
 * @Configuration
 * 
 * @EnableWebSecurity public class MyConfig extends WebSecurityConfiguration {
 * 
 * @Bean public UserDetailsService getUserDetailsService() { return new
 * UserDetailsServiceImpl(); }
 * 
 * @Bean public BCryptPasswordEncoder passwordEncoder() { return new
 * BCryptPasswordEncoder(); }
 * 
 * @Bean public DaoAuthenticationProvider authenticationProvider() {
 * DaoAuthenticationProvider daoAuthenticationProvider = new
 * DaoAuthenticationProvider();
 * daoAuthenticationProvider.setUserDetailsService(getUserDetailsService());
 * daoAuthenticationProvider.setPasswordEncoder(passwordEncoder()); return
 * daoAuthenticationProvider; }
 * 
 * // configure method home page ka navbar khol de kaha hok
 * 
 * @Override protected void configure(AuthenticationManagerBuilder auth) throws
 * Exception { auth.authenticationProvider(authenticationProvider());
 * 
 * }
 * 
 * @Override protected void configure(HttpSecurity http) throws Exception {
 * http.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN").
 * antMatchers("/user/**").hasRole("ROLE_USER")
 * .antMatchers("/**").permitAll().and().formLogin().and().csrf().disable(); } }
 */