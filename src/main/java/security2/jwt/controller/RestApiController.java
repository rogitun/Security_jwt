package security2.jwt.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import security2.jwt.model.User;
import security2.jwt.repository.UserRepository;

@Slf4j
@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final BCryptPasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @GetMapping("/home")
    public String home(){

        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token(){

        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user){
        log.info("join 2323213123213123123");
        System.out.println(user.toString());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "가입 완료";
    }

}
