package com.lib.token.cob.util;

import com.lib.token.cob.model.TokenDetails;
import com.lib.token.cob.model.UserDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;
import java.util.Objects;

/**
 * Utility class for generating, parsing, and validating JSON Web Tokens (JWT).
 * Provides methods to create JWTs with user details, extract claims, and validate tokens.
 */
public class JwtUtil {

    private final Key key;
    private final long expirationMillis;

    public JwtUtil(String SECRET_KEY, long expirationMillis){
        if (SECRET_KEY == null || SECRET_KEY.length() < 32) {
            throw new IllegalArgumentException("Secret key must be at least 256 bits (32 chars base64).");
        }
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
        this.expirationMillis = expirationMillis;
    }

    /**
     * Generates a JWT token for the given user details.
     * This method creates a JSON Web Token (JWT) using the provided user details.
     * The token includes the user's username as the subject, their role as a custom claim,
     * and additional metadata such as the issuer, issued date, and expiration date.
     * The token is signed using the HMAC SHA-256 algorithm and a secret key.
     *
     * @param userDto The user details object containing the username and role.
     *                Must not be null.
     * @return A signed JWT token as a String.
     * @throws NullPointerException if the userDto is null.
     */
    public String generateToken(UserDto userDto) {
        Objects.requireNonNull(userDto, "userDto must not be null");
        return Jwts.builder()
                .setSubject(userDto.getUsername())
                .claim(TokenClaims.ROLE.name(), userDto.getRole()) // Add role as a custom claim.ROLE, userDto.getRole()) // Add role as a custom claim
                .setIssuer(TokenClaims.ISSUER.name())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationMillis)) // 1 hour
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    private Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public TokenDetails getTokenDetails(String token) {
        Claims claims = extractClaims(token);
        TokenDetails tokenDetails = new TokenDetails();
        tokenDetails.setToken(token);
        tokenDetails.setIssuer(claims.getIssuer());
        tokenDetails.setExpireAt(claims.getExpiration());
        tokenDetails.setRole(claims.get(TokenClaims.ROLE.name(), String.class));
        return tokenDetails;
    }

    // Validates the JWT token based on its signature, issuer, and expiration date.
    public boolean validateToken(String token) {
        try{
            Claims claims = extractClaims(token);
            if (!TokenClaims.ISSUER.name().equals(claims.getIssuer())) {
                return false;
            }
            return claims.getExpiration().after(new Date());
        }catch (JwtException | IllegalArgumentException e) {
            // Signature invalid, expired, malformed, etc.
            return false;
        }
    }
}
