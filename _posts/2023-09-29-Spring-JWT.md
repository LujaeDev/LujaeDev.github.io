---
title: Spring JWT
author: lujae
date: 2023-09-29 00:34:00 +0800
categories: [Web, Spring]
tags: [JWT, Authentication, Spring, Spring Security]
toc: true
---

스프링에서 JWT를 사용하게 해주는 라이브러리에는 여러가지가 있다. 그 중에서 내가 참고한 코드는 'com.auth0:java-jwt:4.2.1'를 사용하고 있었다. 하지만 가장 많이 쓰이는 라이브러리는 'io.jsonwebtoken'이기 때문에 'io.jsonwebtoken'를 사용해서 적용해볼 예정이다.

## 사전 준비 코드

### Class Member

```java
package member.domain;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.crypto.password.PasswordEncoder;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Builder
@Table(name = "member")
@AllArgsConstructor

public class Member {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "user_id")
	private Long id;

	private String email;
	private String password;
	private String nickname;
	private String imageUrl;
	private int age;
	private String city;

	@Enumerated(EnumType.STRING)
	private Role role;

	@Enumerated(EnumType.STRING)
	private SocialType socialType; // KAKAO, NAVER, GOOGLE

	private String socialId; // 로그인한 소셜 타입의 식별자 값 (일반 로그인인 경우 null)
	private String refreshToken;

	public void authorizeUser() {
		this.role = Role.USER;
	}

	public void passwordEncode(PasswordEncoder passwordEncoder) {
		this.password = passwordEncoder.encode(this.password);
	}

	public void updateRefreshToken(String updateRefreshToken) {
		this.refreshToken = updateRefreshToken;
	}
}
```

사용자 회원가입시 사용자의 정보를 담을 클래스이며 추후 OAuth를 적용시킬 예정이다. 타 플랫폼에서 제공 하지 않지만 서비스 내에서 필요한 정보를 위해 소셜 로그인 성공시 추가적인 정보 입력 폼을 보여줄 수도 있다.

### Enum Role

```java
@Getter
@RequiredArgsConstructor
public enum Role {

    GUEST("ROLE_GUEST"), USER("ROLE_USER");

    private final String key;
}
```

사용자에게 권한을 차등하여 부여하기 위한 사용자 권한 식별자이다.

### Enum SocialType

```java
public enum SocialType {
	KAKAO, NAVER, GOOGLE
}
```

### Inteface UserRepository

```java
@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByEmail(String email);

    Optional<Member> findByNickname(String nickname);

    Optional<Member> findByRefreshToken(String refreshToken);

    Optional<Member> findBySocialTypeAndSocialId(SocialType socialType, String socialId);
}
```

spring jpa data를 활용하여 구현한다.

### Class MemberService

```java
package member.application;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import member.domain.Member;
import member.domain.MemberRepository;
import member.domain.Role;
import member.dto.request.MemberSignUpDto;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Transactional
@RequiredArgsConstructor
public class MemberService {

	private final MemberRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	public void signUp(MemberSignUpDto memberSignUpDto) throws Exception {

		if (userRepository.findByEmail(memberSignUpDto.getEmail()).isPresent()) {
			throw new Exception("이미 존재하는 이메일입니다.");
		}

		if (userRepository.findByNickname(memberSignUpDto.getNickname()).isPresent()) {
			throw new Exception("이미 존재하는 닉네임입니다.");
		}

		Member member = Member.builder()
			.email(memberSignUpDto.getEmail())
			.password(memberSignUpDto.getPassword())
			.nickname(memberSignUpDto.getNickname())
			.age(memberSignUpDto.getAge())
			.city(memberSignUpDto.getCity())
			.role(Role.USER)
			.build();

		member.passwordEncode(passwordEncoder);
		userRepository.save(member);
	}
}
```

### Class MemberController

```java
package member.presentation;

import lombok.RequiredArgsConstructor;
import member.application.MemberService;
import member.dto.request.MemberSignUpDto;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class MemberController {

    private final MemberService memberService;

    @PostMapping("/sign-up")
    public String signUp(@RequestBody MemberSignUpDto userSignUpDto) throws Exception {
        memberService.signUp(userSignUpDto);
        return "회원가입 성공";
    }

    @GetMapping("/jwt-test")
    public String jwtTest() {
        return "jwtTest 요청 성공";
    }
}
```

## 프로젝트 JWT 관련 설정

### 의존성 추가

build.gradle 파일에 다음과 같은 코드를 추가하여 동기화 시켜주면 JWT 라이브러리에서 제공해주는 코드를 사용할 수 있게 된다.

```
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
```

### application-jwt.yml 설정

src/main/resources/application-jwt.yml 파일에서 JWT 로직을 설계할 때 사용할 변수들을 한 곳에 모아 관리한다.

```
jwt:
  secretKey: VlwEyVBsYt9V7zq57TejMnVUyzblYcfPQye08f7MGVA9XkHa

  access:
    expiration: 3600000 # 1시간
    header: Authorization

  refresh:
    expiration: 1209600000 # 2주
    header: Authorization-refresh
```

개발자가 application-ooo 형식을 가진 파일을 만들면 이를 프로젝트가 실행될 때 포함되도록 설정역시 해줘야한다.

JWT 암호화 알고리즘으로 HS512를 사용할 것이기 때문에, secreKey는 64(512 / 8)bytes 이상이 돼야한다. 하지만 개발자가 설정한 secretKey가 64bytes가 되지 않더라도 알아서 padding을 추가해주기 때문에 **아무 문자열**로 설정해도 된다.

application-ooo의 형태를 가진 파일을 스프링 프로그램 실행시 포함시키기 위해서는 application.properties파일에 다음과 같은 코드를 추가해야한다.

```
#spring.profiles.include=ooo
spring.profiles.include=jwt
```

## JWT 관련 코드

### Class JwtService

'com:auto0:java-jwt'라이브러리를 사용하는 경우 JWT를 생성할 때 **com.auth0.jwt.JWT**를 사용하고 'io.jsonwebtoken'라이브 러리를 사용하는 경우 **io.jsonwebtoken.Jwts**를 사용한다.

```java
package com.example.myJwtOauth.jwt.application;

import com.example.myJwtOauth.member.domain.MemberRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.springframework.security.config.Elements.JWT;

@Service
@Getter
@Slf4j
public class JwtService {
    @Value("${jwt.secretKey}")
    private String secretKey;

    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationPeriod;

    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirationPeriod;

    @Value("${jwt.access.header}")
    private String accessHeader;

    @Value("${jwt.refresh.header}")
    private String refreshHeader;

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String EMAIL_CLAIM = "email";
    private static final String BEARER = "Bearer ";


    private final MemberRepository memberRepository;
    private SecretKey key;

    public JwtService(@Autowired  MemberRepository memberRepository){
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        this.memberRepository = memberRepository;
    }

    public String createAccessToken(String email) {
        Date now = new Date();
        Map<String, Object> userClaim = new HashMap<>();
        userClaim.put(EMAIL_CLAIM, email);

        return Jwts.builder()
                .setSubject(ACCESS_TOKEN_SUBJECT)
                .setExpiration(new Date(now.getTime() + accessTokenExpirationPeriod))
                .addClaims(userClaim)
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public String createRefreshToken() {
        Date now = new Date();

        return Jwts.builder()
                .setSubject(REFRESH_TOKEN_SUBJECT)
                .setExpiration(new Date(now.getTime() + refreshTokenExpirationPeriod))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }

    public void sendAccessToken(HttpServletResponse response, String accessToken) {
        response.setStatus(HttpServletResponse.SC_OK);

        response.setHeader(accessHeader, accessToken);
        log.info("재발급된 Access Token : {}", accessToken);
    }

    public void sendAccessAndRefreshToken(HttpServletResponse response, String accessToken, String refreshToken) {
        response.setStatus(HttpServletResponse.SC_OK);

        setAccessTokenHeader(response, accessToken);
        setRefreshTokenHeader(response, refreshToken);
        log.info("Access Token, Refresh Token 헤더 설정 완료");
    }

    /**
     * 헤더에서 RefreshToken 추출
     * 토큰 형식 : Bearer XXX에서 Bearer를 제외하고 순수 토큰만 가져오기 위해서
     * 헤더를 가져온 후 "Bearer"를 삭제(""로 replace)
     */
    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(refreshHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    /**
     * 헤더에서 AccessToken 추출
     * 토큰 형식 : Bearer XXX에서 Bearer를 제외하고 순수 토큰만 가져오기 위해서
     * 헤더를 가져온 후 "Bearer"를 삭제(""로 replace)
     */
    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(accessHeader))
                .filter(refreshToken -> refreshToken.startsWith(BEARER))
                .map(refreshToken -> refreshToken.replace(BEARER, ""));
    }

    public Optional<String> extractEmail(String accessToken) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();

            String email = claims.get(EMAIL_CLAIM, String.class);


            return email != null ? Optional.of(email) : Optional.empty();
        } catch (Exception e) {
            log.error("액세스 토큰이 유효하지 않습니다.");
            return Optional.empty();
        }
    }

    /**
     * AccessToken 헤더 설정
     */
    public void setAccessTokenHeader(HttpServletResponse response, String accessToken) {
        response.setHeader(accessHeader, accessToken);
    }

    /**
     * RefreshToken 헤더 설정
     */
    public void setRefreshTokenHeader(HttpServletResponse response, String refreshToken) {
        response.setHeader(refreshHeader, refreshToken);
    }

    /**
     * RefreshToken DB 저장(업데이트)
     */
    public void updateRefreshToken(String email, String refreshToken) {
        memberRepository.findByEmail(email)
                .ifPresentOrElse(
                        user -> user.updateRefreshToken(refreshToken),
                        () -> new Exception("일치하는 회원이 없습니다.")
                );
    }

    public boolean isTokenValid(String token) {
        try {
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);

            claims.getBody()
                    .getExpiration()
                    .before(new Date());

            return true;
        } catch (Exception e) {
            log.error("유효하지 않은 토큰입니다. {}", e.getMessage());
            return false;
        }
    }
}
```

- .setSubject(String str)
  JWT에서 payload의 claims은 표준 claim과 사용자 지정 claim로 구분할 수 있다. 표준 claim은 총 7가지 이며 .setSubject()메서드는 표준 claim **sub**를 지정하는 메서드이다. JWT토큰에서 sub claim이 하는 역할은 토큰의 제목을 지정하는 것이다.

## JWT 인증 수행 방식

이번에 구현할 코드는 **RTR**방식이다. Refrest Token Rotation의 약자로 Access Token을 재발급할 때 Refresh Token을 사용하면 기존 Refresh Token을 대체하는 새로운 Refresh Token을 발급하는 방식이다. Refresh Token의 주기 역시 짧게 설정하는 효과를 얻게 되므로 보안상 유리하다. 전반적인 JWT 인증 수행 방식은 사용자가 보낸 Access Token의 만료 여부에 따라 수행 방식이 달라진다.

Acess Token의 만료 기간을 확인하는 것은 Server에서도 할 수 있고 Client에서도 할 수 있다.
Client측 프론트 코드에서 토큰의 페이로드를 해석하여 만료 기간을 알 수 있다. Client에서 만료 기간을 확인할 것 인지, Server에서 만료 기간을 확인할 것 인지는 구현하는 개발자의 선택이며 여기서는 Server에서 만료기간을 확인하는 방식으로 할 예정이다.

### Case1: Access Token이 만료되지 않았을 경우

```
1. 서비스에 자원을 요청할 때 사용자가 Access Token을 포함한 요청을 보냄 (이때 Refresh Token을 포함하지 않은 요청임)
2. Access Token에 대한 검증을 실행
```

### Case2: Access Token이 만료되었을 경우

```
1. 서비스에 자원을 요청할 때 사용자가 Access Token을 포함한 요청을 보냄 (이때 Refresh Token을 포함하지 않은 요청임)
2. 서버가 Access Token이 만료됨을 확인하고 클라이언트에게 이를 알려줌
3. 클라이언트는 같은 내용의 요청을 Access Token과 Refresh Token을 담아서 서버로 보냄
4. Refresh Token이 유효한 경우 Access Token을 다시 발급해주고 RTR방식을 사용하는 경우 Refres Token까지 재발급함
```

이런 인증 과정들은 서버에서 컨트롤러가 동작하기 전에 수행되어야 한다. 그렇기 때문에 이런 인증 과정들은 요청이 DispatcherServlet에 도달하기 전 Filter 상에서 처리된다.

```java
package com.example.myJwtOauth.jwt.presentation;

import com.example.myJwtOauth.jwt.application.JwtService;
import com.example.myJwtOauth.jwt.utils.PasswordUtil;
import com.example.myJwtOauth.member.domain.Member;
import com.example.myJwtOauth.member.domain.MemberRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Jwt 인증 필터
 * "/login" 이외의 URI 요청이 왔을 때 처리하는 필터
 *
 * 기본적으로 사용자는 요청 헤더에 AccessToken만 담아서 요청
 * AccessToken 만료 시에만 RefreshToken을 요청 헤더에 AccessToken과 함께 요청
 *
 * 1. RefreshToken이 없고, AccessToken이 유효한 경우 -> 인증 성공 처리, RefreshToken을 재발급하지는 않는다.
 * 2. RefreshToken이 없고, AccessToken이 없거나 유효하지 않은 경우 -> 인증 실패 처리, 403 ERROR
 * 3. RefreshToken이 있는 경우 -> DB의 RefreshToken과 비교하여 일치하면 AccessToken 재발급, RefreshToken 재발급(RTR 방식)
 *                              인증 성공 처리는 하지 않고 실패 처리
 *
 */
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationProcessingFilter extends OncePerRequestFilter {

    private static final String NO_CHECK_URL = "/login"; // "/login"으로 들어오는 요청은 Filter 작동 X

    private final JwtService jwtService;
    private final MemberRepository memberRepository;

    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getRequestURI().equals(NO_CHECK_URL)) {
            filterChain.doFilter(request, response); // "/login" 요청이 들어오면, 다음 필터 호출
            return; // return으로 이후 현재 필터 진행 막기 (안해주면 아래로 내려가서 계속 필터 진행시킴)
        }

        String refreshToken = jwtService.extractRefreshToken(request)
                .filter(jwtService::isTokenValid)
                .orElse(null);

        if (refreshToken == null) {
            checkAccessTokenAndAuthentication(request, response, filterChain);
        }else{
            if(jwtService.isTokenValid(refreshToken))
                checkRefreshTokenAndReIssueAccessToken(response, refreshToken);
            else{
                //refresh token이 만료되었으니까 사용자는 다시 로그인해야함
            }
        }
    }

    /**
     *  [리프레시 토큰으로 유저 정보 찾기 & 액세스 토큰/리프레시 토큰 재발급 메소드]
     *  파라미터로 들어온 헤더에서 추출한 리프레시 토큰으로 DB에서 유저를 찾고, 해당 유저가 있다면
     *  JwtService.createAccessToken()으로 AccessToken 생성,
     *  reIssueRefreshToken()로 리프레시 토큰 재발급 & DB에 리프레시 토큰 업데이트 메소드 호출
     *  그 후 JwtService.sendAccessTokenAndRefreshToken()으로 응답 헤더에 보내기
     */
    public void checkRefreshTokenAndReIssueAccessToken(HttpServletResponse response, String refreshToken) {
        memberRepository.findByRefreshToken(refreshToken)
                .ifPresent(member -> {
                    String reIssuedRefreshToken = reIssueRefreshToken(member);
                    jwtService.sendAccessAndRefreshToken(response, jwtService.createAccessToken(member.getEmail()),
                            reIssuedRefreshToken);
                });
    }

    /**
     * [리프레시 토큰 재발급 & DB에 리프레시 토큰 업데이트 메소드]
     * jwtService.createRefreshToken()으로 리프레시 토큰 재발급 후
     * DB에 재발급한 리프레시 토큰 업데이트 후 Flush
     */
    private String reIssueRefreshToken(Member member) {
        String reIssuedRefreshToken = jwtService.createRefreshToken();
        member.updateRefreshToken(reIssuedRefreshToken);
        memberRepository.saveAndFlush(member);
        return reIssuedRefreshToken;
    }

    /**
     * [액세스 토큰 체크 & 인증 처리 메소드]
     * request에서 extractAccessToken()으로 액세스 토큰 추출 후, isTokenValid()로 유효한 토큰인지 검증
     * 유효한 토큰이면, 액세스 토큰에서 extractEmail로 Email을 추출한 후 findByEmail()로 해당 이메일을 사용하는 유저 객체 반환
     * 그 유저 객체를 saveAuthentication()으로 인증 처리하여
     * 인증 허가 처리된 객체를 SecurityContextHolder에 담기
     * 그 후 다음 인증 필터로 진행
     */
    public void checkAccessTokenAndAuthentication(HttpServletRequest request, HttpServletResponse response,
                                                  FilterChain filterChain) throws ServletException, IOException {
        log.info("checkAccessTokenAndAuthentication() 호출");
        jwtService.extractAccessToken(request)
                .filter(jwtService::isTokenValid)
                .ifPresent(accessToken -> jwtService.extractEmail(accessToken)
                        .ifPresent(email -> memberRepository.findByEmail(email)
                                .ifPresent(this::saveAuthentication)));

        filterChain.doFilter(request, response);
    }

    /**
     * [인증 허가 메소드]
     * 파라미터의 유저 : 우리가 만든 회원 객체 / 빌더의 유저 : UserDetails의 User 객체
     *
     * new UsernamePasswordAuthenticationToken()로 인증 객체인 Authentication 객체 생성
     * UsernamePasswordAuthenticationToken의 파라미터
     * 1. 위에서 만든 UserDetailsUser 객체 (유저 정보)
     * 2. credential(보통 비밀번호로, 인증 시에는 보통 null로 제거)
     * 3. Collection < ? extends GrantedAuthority>로,
     * UserDetails의 User 객체 안에 Set<GrantedAuthority> authorities이 있어서 getter로 호출한 후에,
     * new NullAuthoritiesMapper()로 GrantedAuthoritiesMapper 객체를 생성하고 mapAuthorities()에 담기
     *
     * SecurityContextHolder.getContext()로 SecurityContext를 꺼낸 후,
     * setAuthentication()을 이용하여 위에서 만든 Authentication 객체에 대한 인증 허가 처리
     */
    public void saveAuthentication(Member myMember) {
        String password = myMember.getPassword();

        if (password == null) { // 소셜 로그인 유저의 비밀번호 임의로 설정 하여 소셜 로그인 유저도 인증 되도록 설정
            password = PasswordUtil.generateRandomPassword();
        }

        UserDetails userDetailsUser = User.builder()
                .username(myMember.getEmail())
                .password(password)
                .roles(myMember.getRole().name())
                .build();

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(userDetailsUser, null,
                        authoritiesMapper.mapAuthorities(userDetailsUser.getAuthorities()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
```

### Authentication 저장 과정

**JwtAuthenticationProcessingFilter.saveAuthentication()** 메서드에서 Spring Security를 활용하여 인증 객체를 저장한다.

![jwt security structure](/assets/img/posts/jwt_security_structure.png)

#### UserDetails

인증에 성공한 사용자는 자신의 정보를 바탕으로 Authentication 객체 생성을 위한 UserDetails객체를 만든다.

#### UsernamePasswordAuthenticationToken

Authentication을 implements한 AbstractAuthenticationToken의 하위 클래스로, User의 ID가 Principal 역할을 하고, Password가 Credential의 역할을 한다.

UsernamePasswordAuthenticationToken에는 2가지 생성자가 있다. 첫 번째 생성자는 인증 전 객체를 표현하기 위해 사용되고, 두 번째 생성자는 인증 완료 후 객체를 표현하기 위해 사용한다. JwtAuthenticationProcessingFilter.saveAuthentication() 메서드에서는 두 번째 사용자를 사용했다.

```java

	public UsernamePasswordAuthenticationToken(Object principal, Object credentials) {
		super(null);
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(false);
	}

	public UsernamePasswordAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		super.setAuthenticated(true); // must use super, as we override
	}
```

아래는 필터의 인증 객체 저장 과정에서 UsernamePasswordAuthenticationToken을 생성하는 부분을 발췌한 것이다. 이때 특이한 것이 credentials이 null인데 이는 추 후 OAuth를 통해 소셜 로그인 기능을 추가할 경우를 대비한 것이다. 소셜 로그인을 사용하는 경우 비밀번호를 입력받지 않기 때문에 credentials을 null로 설정하였다.

```java
Authentication authentication =
                new UsernamePasswordAuthenticationToken(userDetailsUser, null,
                        authoritiesMapper.mapAuthorities(userDetailsUser.getAuthorities()));
```

#### Authentication

현재 접근하는 주체의 정보와 권한을 담는 인터페이스이다. Authentication 객체는 SecurityContext에 저장되며, SecurityContextHolder를 통해 SecurityContext에 접근하고, SecurityContext를 통해 Authentication에 접근할 수 있다.

## 참고

https://ksh-coding.tistory.com/59

https://mangkyu.tistory.com/76

https://dev-coco.tistory.com/174
