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

public class JwtUtil {

    private static final String SECRET_KEY = "Y29ycmVjdC1zZWNyZXQta2V5LXN0b3JlZC1zYWZlbHk=";
    private final Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));

    public String generateToken(UserDto userDto) {
        return Jwts.builder()
                .setSubject(userDto.getUserName())
                .claim("role", userDto.getRole()) // Add role as a custom claim
                .setIssuer("COB-Portal")
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour
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
        tokenDetails.setRole(claims.get("role", String.class));
        return tokenDetails;
    }

    public boolean validateToken(String token) {
        try{
            Claims claims = extractClaims(token);
            return claims.getExpiration().after(new Date());
        }catch (JwtException | IllegalArgumentException e) {
            // Signature invalid, expired, malformed, etc.
            return false;
        }
    }
}
