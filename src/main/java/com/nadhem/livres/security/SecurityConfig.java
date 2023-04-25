package com.nadhem.livres.security;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfiguration{
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	 
	auth.inMemoryAuthentication().withUser("admin").password("{noop}123").roles("ADMIN");
	auth.inMemoryAuthentication().withUser("nadhem").password("{noop}123").roles("AGENT","USER");
	auth.inMemoryAuthentication().withUser("user1").password("{noop}123").roles("USER");
	 }
	 
	 protected void configure(HttpSecurity http) throws Exception {
	 http.authorizeHttpRequests().anyRequest().authenticated();
         http.formLogin(withDefaults());
	 }
}
