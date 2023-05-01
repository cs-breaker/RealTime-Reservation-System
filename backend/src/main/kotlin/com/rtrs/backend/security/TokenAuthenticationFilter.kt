package com.rtrs.backend.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.util.StringUtils
import org.springframework.web.filter.OncePerRequestFilter

class TokenAuthenticationFilter: OncePerRequestFilter() {

    val AUTHORIZATION_HEADER = "Authorization"
    val BEARER_PREFIX = "Bearer "

    fun resolveToken(request: HttpServletRequest): String? {
        val bearerToken = request.getHeader(AUTHORIZATION_HEADER)
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length)
        }
        return null
    }

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val jwt = resolveToken(request)

//        if(StringUtils.hasText(jwt) && )
    }
}