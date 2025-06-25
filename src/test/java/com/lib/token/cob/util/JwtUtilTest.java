package com.lib.token.cob.util;

import com.lib.token.cob.model.TokenDetails;
import com.lib.token.cob.model.UserDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.*;

class JwtUtilTest {

    private JwtUtil jwtUtil;
    private final String secretKey = Base64.getEncoder().encodeToString("my-very-secure-and-long-secret-key-123456".getBytes());
    private final long expirationMillis = 1000 * 60 * 60; // 1 hour

    private UserDto user;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil(secretKey, expirationMillis);
        user = new UserDto();
        user.setUsername("testUser");
        user.setRole("ADMIN");
    }

    @Test
    void generateToken_shouldReturnValidToken() {
        String token = jwtUtil.generateToken(user);
        assertThat(token).isNotNull().isNotEmpty();
    }

    @Test
    void validateToken_shouldReturnTrueForValidToken() {
        String token = jwtUtil.generateToken(user);
        assertThat(jwtUtil.validateToken(token)).isTrue();
    }

    @Test
    void validateToken_shouldReturnFalseForInvalidToken() {
        String invalidToken = "invalid.token.value";
        assertThat(jwtUtil.validateToken(invalidToken)).isFalse();
    }

    @Test
    void getTokenDetails_shouldExtractCorrectClaims() {
        String token = jwtUtil.generateToken(user);
        TokenDetails details = jwtUtil.getTokenDetails(token);

        assertThat(details.getToken()).isEqualTo(token);
        assertThat(details.getRole()).isEqualTo("ADMIN");
        assertThat(details.getIssuer()).isEqualTo(TokenClaims.ISSUER.getClaimName());
        assertThat(details.getExpireAt()).isAfter(new Date());
    }

    @Test
    void validateToken_shouldReturnFalseForWrongIssuer() {
        // Manually create a token with a different issuer
        String wrongIssuerToken = io.jsonwebtoken.Jwts.builder()
                .setSubject(user.getUsername())
                .claim(TokenClaims.ROLE.name(), user.getRole())
                .setIssuer("WRONG_ISSUER")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMillis))
                .signWith(io.jsonwebtoken.security.Keys.hmacShaKeyFor(java.util.Base64.getDecoder().decode(secretKey)), io.jsonwebtoken.SignatureAlgorithm.HS256)
                .compact();

        assertThat(jwtUtil.validateToken(wrongIssuerToken)).isFalse();
    }

    @Test
    void generateToken_shouldThrowExceptionForNullUser() {
        assertThatThrownBy(() -> jwtUtil.generateToken(null))
                .isInstanceOf(NullPointerException.class);
    }
}