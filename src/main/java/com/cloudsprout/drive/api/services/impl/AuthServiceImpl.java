package com.cloudsprout.drive.api.services.impl;

import java.util.Optional;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;

import com.cloudsprout.drive.api.domain.dto.user.LoginDTO;
import com.cloudsprout.drive.api.domain.dto.user.AuthResponseDTO;
import com.cloudsprout.drive.api.domain.entities.User;
import com.cloudsprout.drive.api.repositories.IUserRepository;
import com.cloudsprout.drive.api.services.IAuthService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements IAuthService {

  private final IUserRepository userRepository;

  @Override
  public AuthResponseDTO login(LoginDTO dto) {
    Optional<User> user = userRepository.findByEmail(dto.getEmail());

    if (user.isEmpty()) {
      throw new BadCredentialsException("Invalid credentials");
    }

    return AuthResponseDTO.builder().token("token").user(new User()).build();
  }

}
