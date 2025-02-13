package com.cloudsprout.drive.api.domain.dto.user;

import com.cloudsprout.drive.api.domain.entities.User;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserResponseDTO {
  private User user;
}
