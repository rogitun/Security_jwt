package security2.jwt.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import security2.jwt.model.User;
import security2.jwt.repository.UserRepository;

//http://localhost:8080/login 시 동작
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {


    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("principalDetailService LoadByUserName_action");
        User user = userRepository.findByUsername(username);
        System.out.println("user entity : " + user);
        return new PrincipalDetails(user);
    }
}
