package com.rtrs.backend.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.AccessDeniedHandler

@Configuration
class SecurityConfig(private val customAccessDeniedHandler: AccessDeniedHandler) {

    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http.authorizeHttpRequests()
            .requestMatchers("/login/**")
            .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .httpBasic().disable()
            .formLogin().disable()
            .csrf().disable()
            .cors() // TODO: cors config 설정해야 함
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .exceptionHandling()
            .accessDeniedHandler(customAccessDeniedHandler)

        return http.build()
    }
}