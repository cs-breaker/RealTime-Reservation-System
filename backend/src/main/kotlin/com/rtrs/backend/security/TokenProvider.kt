package com.rtrs.backend.security

import io.jsonwebtoken.*
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.security.Key

import io.jsonwebtoken.io.*
import io.jsonwebtoken.security.*
import io.jsonwebtoken.security.SignatureException
import mu.KotlinLogging
import org.springframework.security.core.Authentication
import java.util.Date

@Component
class TokenProvider(@Value("#{jwt.secret}") secretKey: String) {

    val logger = KotlinLogging.logger {}

    val ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 60
    val REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24
    val BEARER_PREFIX = "Bearer "

    private val key: Key

    init {
        val keyBytes = Decoders.BASE64.decode(secretKey)
        this.key = Keys.hmacShaKeyFor(keyBytes)
    }

    /**
     * Authentication으로부터 access, refresh token 생성
     */
    fun generateToken(authentication: Authentication): TokenDto {
        // TODO : Authorities, ParseClaims 쪽 나중에 다시 확인

        val now = Date().time
        val accessTokenExpire = Date(now + ACCESS_TOKEN_EXPIRE_TIME)
        val refreshTokenExpire = Date(now + REFRESH_TOKEN_EXPIRE_TIME)

        val accessToken = Jwts.builder()
            .setSubject(authentication.name)
            .setExpiration(accessTokenExpire)
            .signWith(key, SignatureAlgorithm.HS512)
            .compact()

        val refreshToken = Jwts.builder()
            .setExpiration(refreshTokenExpire)
            .signWith(key, SignatureAlgorithm.HS512)
            .compact()

        return TokenDto(
            grantType = BEARER_PREFIX,
            accessToken = accessToken,
            accessTokenExpire = accessTokenExpire.time,
            refreshToken = refreshToken,
            refreshTokenExpire = refreshTokenExpire.time
        )
    }

    /**
     * 토큰 유효성 검증
     */
    fun validateToken(token: String): Boolean {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token)
            return true
        } catch (ex: SignatureException) {
            logger.info("Invalid JWT signature");
        } catch (ex: MalformedJwtException) {
            logger.info("Invalid JWT token");
        } catch (ex: ExpiredJwtException) {
            logger.info("Expired JWT token");
        } catch (ex: UnsupportedJwtException) {
            logger.info("Unsupported JWT token");
        } catch (ex: IllegalArgumentException) {
            logger.info("JWT claims string is empty");
        }
        return false
    }
}

data class TokenDto(
    val grantType: String,
    val accessToken: String,
    val accessTokenExpire: Long,
    val refreshToken: String,
    val refreshTokenExpire: Long,
)