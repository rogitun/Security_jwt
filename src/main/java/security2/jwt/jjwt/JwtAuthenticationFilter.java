package security2.jwt.jjwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import security2.jwt.auth.PrincipalDetails;
import security2.jwt.model.User;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

//스프링 시큐리티에 UsernamePasswordAuthenticationFilter가 있다.
// /login 요청하면 username, password 전송하면
// UsernamePasswordAuthenticationFilter 동작
// 현재 form.login이 disable이라 작동 안한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    //login 요청을 하면 로그인 시도를 위해 실행되는 함수임.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("jwtAuthenticationFilter : 시도");
        // 1. username, pwd 받아서 정상인지 확인한다.
        // 2 .authenticationManager로 로그인 시도하면 principalDetailsService 호출
        // 3. -> LoaduserByusername 실행
        // 4. principalDetails를 세션에 담는다 (권한 관리 때문에 프린시펄을 세션을 담는것)
        // 5. JWt 토큰을 만들어서 응답
        try {

            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(),User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken token =
                    new UsernamePasswordAuthenticationToken(user.getUsername(),user.getPassword());

            //principalDetailsService의 loadByUsername 함수 실행, 토큰의 username만 가지고 처리, pwd는 스프링이 처리
            Authentication authentication =
                    authenticationManager.authenticate(token);

            //authentication 객체가 session 영역에 저장됨. => 로그인 되었음
            PrincipalDetails principalDetails =(PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername() + " <= UserName");
            System.out.println("+++++++++++++++++++++++++++++");
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("==========================");
        return null;
    }
}
