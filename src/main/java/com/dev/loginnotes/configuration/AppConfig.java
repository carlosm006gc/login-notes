package com.dev.loginnotes.configuration;

import com.dev.loginnotes.session.SessionFilter;
import com.dev.loginnotes.user.CurrentUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class AppConfig {
    @Autowired
    private CurrentUserService currentUserService;
    @Autowired
    private SessionFilter sessionFilter;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, BCryptPasswordEncoder bCryptPasswordEncoder, CurrentUserService currentUserService)
            throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(currentUserService)
                .passwordEncoder(bCryptPasswordEncoder)
                .and()
                .build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http = http.cors().and().csrf().disable();

        http = http.exceptionHandling().authenticationEntryPoint(
                (request, response, ex) -> response.sendError(
                        HttpServletResponse.SC_UNAUTHORIZED,
                        ex.getMessage())
        ).and();

        http.authorizeHttpRequests()
                .requestMatchers("/api/login").permitAll()
                .anyRequest().authenticated();

        http.addFilterBefore(
                sessionFilter,
                UsernamePasswordAuthenticationFilter.class
        );
        return http.build();
    }

    @Bean (name = "passwordEncoder")
    public static BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}