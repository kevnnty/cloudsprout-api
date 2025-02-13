package com.cloudsprout.drive.api.services;

import com.cloudsprout.drive.api.domain.dto.user.LoginDTO;
import com.cloudsprout.drive.api.domain.dto.user.AuthResponseDTO;

public interface IAuthService {
  AuthResponseDTO login(LoginDTO dto);
}
