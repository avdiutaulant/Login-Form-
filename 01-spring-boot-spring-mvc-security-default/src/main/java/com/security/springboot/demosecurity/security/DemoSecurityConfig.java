package com.security.springboot.demosecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;
import java.net.http.HttpRequest;

@Configuration
public class DemoSecurityConfig {

    
    // this is for custom tables that we create in database that spring need to know to read this custom tables
    // I configured spring security to use our custom database tables
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource){
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);

        // define query to retrieve a user by username
        jdbcUserDetailsManager.setUsersByUsernameQuery(
                "select user_id, pw, active from members where user_id=? "
        );

        // define query to retrieve the authorities/roles by username
                jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(
                        "select user_id, role from roles where user_id=?"
                );

        return jdbcUserDetailsManager;
    }
    
    
    // this is for none and bcrypt algorithm with tables that spring security have their tables
//    @Bean
//    public UserDetailsManager userDetailsManager(DataSource dataSource){
//        return new JdbcUserDetailsManager(dataSource);
//    }


/*

// this is hard coded without databases
    @Bean
    public InMemoryUserDetailsManager userDetailsManager(){

        UserDetails sara = User.builder()
                .username("sara")
                .password("{noop}test123")
                .roles("EMPLOYEE")
                .build();

        UserDetails erda = User.builder()
                .username("erda")
                .password("{noop}test123")
                .roles("EMPLOYEE", "MANAGER")
                .build();

        UserDetails taulanti = User.builder()
                .username("taulanti")
                .password("{noop}test123")
                .roles("EMPLOYEE","MANAGER","ADMIN")
                .build();

        return new InMemoryUserDetailsManager(sara,erda,taulanti);
    }
*/


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    http.authorizeHttpRequests(configurer ->
            configurer
                    .requestMatchers("/").hasRole("EMPLOYEE")
                    .requestMatchers("/leaders/**").hasRole("MANAGER")
                    .requestMatchers("/systems/**").hasRole("ADMIN")
                    .anyRequest().authenticated())
            .formLogin(form->
                    form
                            .loginPage("/showMyLoginPage")
                            .loginProcessingUrl("/authenticateTheUser")
                            .permitAll()

            )
            .logout(logut-> logut.permitAll()
            )
            .exceptionHandling(configurer->
                    configurer.accessDeniedPage("/access-denied"))
    ;

            return http.build();
    }
}
