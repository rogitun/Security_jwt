package security2.jwt.jjwt;

//시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter가 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을때 위 필터를 무조건 타게 되어 있다.
// 만약 권한이 인증이 필요한 주소가 아니라면 필터를 거치지 않는다.

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import security2.jwt.auth.PrincipalDetails;
import security2.jwt.model.User;
import security2.jwt.repository.UserRepository;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager,UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    //인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 거치게 된다.

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //super.doFilterInternal(request, response, chain); 응답이 중복됨, 지워야함
        System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader = " +  jwtHeader);
        //jwt 토큰을 검증해서 정상적인 사용자인지 확인한다.

        //header 가 있는지 확인
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request,response);
            return;
        }

        String jwtToken = request.getHeader("Authorization").replace("Bearer ","");
        //=> Bearer를 제외한 토큰만

        //getClaim은  .withClaim("username", principalDetails.getUser().getUsername())을 의미함.
        String username = JWT
                .require(Algorithm.HMAC512("userToken"))
                .build().verify(jwtToken)
                .getClaim("username")
                .asString();

        //서명 완료
        if(username != null ){
            User entity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(entity);

            //JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails,entity.getPassword(),principalDetails.getAuthorities());

            //강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request,response);
        }
    }
}
