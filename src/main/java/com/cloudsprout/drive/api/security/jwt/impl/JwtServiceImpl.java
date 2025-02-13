package com.cloudsprout.drive.api.security.jwt.impl;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import com.cloudsprout.drive.api.security.jwt.JwtService;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtServiceImpl implements JwtService {

  @Value("${jwt.secret}")
  private String SECRET_KEY;

  @Value("${jwt.expiration}")
  private Integer EXPIRATION_TIME;

  public Key getSigningKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  @Override
  public String generateToken(String email) {
    return Jwts.builder()
        .setSubject(email)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
        .signWith(getSigningKey())
        .compact();
  }

  @Override
  public String extractEmail(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  private Claims extractAllClaims(String token) {
    return Jwts.parserBuilder()
        .setSigningKey(getSigningKey())
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  @Override
  public boolean isTokenValid(String token, String email) {
    final String extractedEmail = extractEmail(token);
    return (extractedEmail.equals(email) && !isTokenExpired(token));
  }

  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }
}
