package com.cloudsprout.drive.api.security.jwt;

public interface JwtService {
  String generateToken(String username);
  String extractEmail(String token);
  boolean isTokenValid(String token, String username);
}
