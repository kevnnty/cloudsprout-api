package com.cloudsprout.drive.api.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cloudsprout.drive.api.domain.dto.user.CreateUserDTO;
import com.cloudsprout.drive.api.domain.dto.user.UserResponseDTO;
import com.cloudsprout.drive.api.payload.ApiResponse;
import com.cloudsprout.drive.api.services.IUserService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/users/accounts")
@RequiredArgsConstructor
public class UserController {

    private final IUserService userService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserResponseDTO>> register(@RequestBody CreateUserDTO dto) {
        try {
            UserResponseDTO newUser = userService.createUser(dto);
            return ApiResponse.success("Account created", HttpStatus.CREATED, newUser);
        } catch (Exception e) {
            return ApiResponse.success(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR, null);
        }
    }

}
