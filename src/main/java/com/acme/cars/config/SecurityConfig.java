package com.acme.cars.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;


import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration conf) {
        try {
            return conf.getAuthenticationManager();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails userComum = User.withUsername("user").password(passwordEncoder().encode("123456")).roles("USER").build();
        UserDetails userAdmin = User.withUsername("admin").password(passwordEncoder().encode("123456")).roles("ADMIN").build();
        return new InMemoryUserDetailsManager(userComum,userAdmin);
    }
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
        .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
            .requestMatchers("/login").permitAll()
            .requestMatchers("/api/usuarios/login").permitAll()
            .requestMatchers(HttpMethod.GET,"/api/carros/**").hasAnyRole("USER","ADMIN")
            .requestMatchers(HttpMethod.POST,"/api/carros/**").hasRole("ADMIN")
            .requestMatchers(HttpMethod.PUT,"/api/carros/**").hasRole("ADMIN")
            .requestMatchers(HttpMethod.DELETE,"/api/carros/**").hasRole("ADMIN")
            )
            .httpBasic(AbstractHttpConfigurer::disable)
            .build();
        }
}
