import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cloudsprout.drive.api.domain.entities.User;
import com.cloudsprout.drive.api.repositories.IUserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

  private final IUserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    // Fetch the user from the database (adjust this to your own logic)
    User userEntity = userRepository.findByEmail(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));

    // Return a UserDetails object (adjust this to match your user entity)
    return User.builder()
        .username(userEntity.getUsername())
        .password(userEntity.getPassword())
        .authorities(userEntity.getAuthorities()) // You can specify roles/authorities here
        .build();
  }
}
