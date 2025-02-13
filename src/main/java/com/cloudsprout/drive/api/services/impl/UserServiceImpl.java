package com.cloudsprout.drive.api.services.impl;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.cloudsprout.drive.api.domain.dto.user.CreateUserDTO;
import com.cloudsprout.drive.api.domain.dto.user.UserResponseDTO;
import com.cloudsprout.drive.api.domain.entities.User;
import com.cloudsprout.drive.api.domain.mappers.UserMapper;
import com.cloudsprout.drive.api.repositories.IUserRepository;
import com.cloudsprout.drive.api.services.IUserService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements IUserService {

  private final IUserRepository userRepository;

  private final UserMapper userMapper;

  @Override
  public User createUserEntity(CreateUserDTO dto) {
    Optional<User> existingUser = userRepository.findByEmail(dto.getEmail());
    if (existingUser.isPresent()) {
      // throw custom global exception here so that it is handled properly by api as a
      throw new RuntimeException("Email already in use");
    }

    User newUser = new User();
    newUser.setEmail(dto.getEmail());
    newUser.setPassword(dto.getPassword());
    return newUser;
  }

  @Override
  public UserResponseDTO createUser(CreateUserDTO dto) {
    User newUser = createUserEntity(dto);
    User savedUser = userRepository.save(newUser);
    return userMapper.userToUserResponseDTO(savedUser);
  }
}
