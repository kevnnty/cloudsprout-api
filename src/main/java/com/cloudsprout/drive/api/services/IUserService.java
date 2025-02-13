package com.cloudsprout.drive.api.services;

import com.cloudsprout.drive.api.domain.dto.user.CreateUserDTO;
import com.cloudsprout.drive.api.domain.dto.user.UserResponseDTO;
import com.cloudsprout.drive.api.domain.entities.User;

public interface IUserService {
  User createUserEntity(CreateUserDTO dto);
  UserResponseDTO createUser(CreateUserDTO dto);
  
}
