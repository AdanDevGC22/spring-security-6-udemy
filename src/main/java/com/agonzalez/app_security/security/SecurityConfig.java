package com.agonzalez.app_security.security;

import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;
import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        var requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName("_csrf");
        httpSecurity.authorizeHttpRequests(auth ->
                //auth.requestMatchers("/loans","/balance","/accounts","/cards")
                        auth
                        .requestMatchers("/loans").hasAuthority("VIEW_LOANS")
                        .requestMatchers("/balance").hasAuthority("VIEW_BALANCE")
                        .requestMatchers("/cards").hasAuthority("VIEW_CARDS")
                        //.requestMatchers("/accounts").hasAnyAuthority("VIEW_ACCOUNT","VIEW_CARDS")
                        .anyRequest().permitAll())
                //auth.anyRequest().authenticated()) //cualquier request que sea mandado debe tener autenticación
                .formLogin(Customizer.withDefaults()) //esto configura mi ventanita de login
                .httpBasic(Customizer.withDefaults()); //Esto es para configurar que mi metodo de autenticación se de
                // tipo HTTP BASIC, que es usuario y contraseña basicamente
        httpSecurity.cors(cors -> corsConfigurationSource());
        httpSecurity.csrf(csrf -> csrf
                .csrfTokenRequestHandler(requestHandler)
                .ignoringRequestMatchers("/welcome","/about_us")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
        return httpSecurity.build();
    }
/*
    @Bean
    InMemoryUserDetailsManager inMemoryUserDetailsManager(){
        UserDetails admin = User.withUsername("admin")
                .password("to_be_encoded")
                .authorities("ADMIN")
                .build();

        UserDetails user = User.withUsername("user")
                .password("to_be_encoded")
                .authorities("USER")
                .build();

        return new InMemoryUserDetailsManager(admin,user);
    }

 */
/*
    @Bean
    UserDetailsService userDetailsService(DataSource dataSource){
        return new JdbcUserDetailsManager(dataSource);
    }
*/
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
    //vamos a configurar los CORS
    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        var config = new CorsConfiguration();
        //pasamos una lista con los origenes que están permitidos
        //config.setAllowedOrigins(List.of("http://localhost:4200/","http://my-aoo.com"));
        config.setAllowedOrigins(List.of("*"));
        //config.setAllowedMethods(List.of("GET","POST","PUT","DELETE"));
        config.setAllowedMethods(List.of("*"));
        config.setAllowedHeaders(List.of("*"));

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",config);

        return source;
    }
}
