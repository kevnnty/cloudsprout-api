package com.cloudsprout.drive.api.domain.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;

import com.cloudsprout.drive.api.domain.dto.user.CreateUserDTO;
import com.cloudsprout.drive.api.domain.dto.user.UserResponseDTO;
import com.cloudsprout.drive.api.domain.entities.User;

@Mapper(componentModel = "spring") // This tells Spring to manage the mapper as a bean
public interface UserMapper {

  UserMapper INSTANCE = Mappers.getMapper(UserMapper.class);
  UserResponseDTO userToUserResponseDTO(User user);
  
  @Mapping(target = "id", ignore = true)
  User createUserDtoToUser(CreateUserDTO createUserDTO);
}