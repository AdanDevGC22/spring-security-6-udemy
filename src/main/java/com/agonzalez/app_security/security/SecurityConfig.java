package com.agonzalez.app_security.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(auth ->
                auth.requestMatchers("/loans","/balance","/accounts","/cards").authenticated()
                        .anyRequest().permitAll())
                //auth.anyRequest().authenticated()) //cualquier request que sea mandado debe tener autenticación
                .formLogin(Customizer.withDefaults()) //esto configura mi ventanita de login
                .httpBasic(Customizer.withDefaults()); //Esto es para configurar que mi metodo de autenticación se de
                // tipo HTTP BASIC, que es usuario y contraseña basicamente
        return httpSecurity.build();
    }
}
