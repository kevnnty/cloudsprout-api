package com.cloudsprout.drive.api.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cloudsprout.drive.api.domain.dto.user.AuthResponseDTO;
import com.cloudsprout.drive.api.domain.dto.user.LoginDTO;
import com.cloudsprout.drive.api.payload.ApiResponse;
import com.cloudsprout.drive.api.services.IAuthService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

  private final IAuthService authService;

  @PostMapping("/login")
  public ResponseEntity<ApiResponse<AuthResponseDTO>> login(@RequestBody LoginDTO dto) {
    try {
      AuthResponseDTO loggedInUser = authService.login(dto);
      return ApiResponse.success("Account created", HttpStatus.CREATED, loggedInUser);
    } catch (Exception e) {
      return ApiResponse.success(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR, null);

    }
  }
}
