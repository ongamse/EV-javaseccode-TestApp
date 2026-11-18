package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.util.CookieUtils;
import org.joychou.util.JwtUtils;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 *
 */
@Slf4j
@RestController
@RequestMapping("/jwt")
public class Jwt {

    private static final String COOKIE_NAME = "USER_COOKIE";
    /**
     * http://localhost:8080/jwt/createToken
     * Create jwt token and set token to cookies.
     *
     * @author JoyChou 2022-09-20
     */
    @GetMapping("/createToken")
    public String createToken(HttpServletResponse response, HttpServletRequest request) {
        String loginUser = request.getUserPrincipal().getName();
        log.info("Current login user is " + loginUser);

        CookieUtils.deleteCookie(response, COOKIE_NAME);
        String token = JwtUtils.generateTokenByJavaJwt(loginUser);
        Cookie cookie = new Cookie(COOKIE_NAME, token);

        cookie.setMaxAge(86400);    // 1 DAY
        cookie.setPath("/");
        cookie.setSecure(true);
        response.addCookie(cookie);
        return "Add jwt token cookie successfully. Cookie name is USER_COOKIE";
    }


    /**
     * http://localhost:8080/jwt/getName
     * Get nickname from USER_COOKIE
     *
     * @author JoyChou 2022-09-20
     * @param user_cookie cookie
     * @return nickname
     */
@GetMapping("/getName")
public ResponseEntity<String> getNickname(@CookieValue(COOKIE_NAME) String user_cookie) {
    String nickname = JwtUtils.getNicknameByJavaJwt(user_cookie);
    if (nickname == null) {
        return ResponseEntity.badRequest().body("Invalid JWT token");
    }
    
    // Input validation before encoding to reject potentially malicious inputs
    if (!Pattern.matches("[a-zA-Z0-9_\\s]+", nickname)) {
        return ResponseEntity.badRequest().body("Nickname contains invalid characters");
    }
    
    // Applied HTML encoding to prevent XSS attacks
    String encodedNickname = StringEscapeUtils.escapeHtml4(nickname);
    
    // For JavaScript contexts (if the nickname is used in JavaScript)
    String jsEncodedNickname = StringEscapeUtils.escapeEcmaScript(nickname);
    
    // Return response with Content-Security-Policy header for defense-in-depth
    return ResponseEntity.ok()
        .header("Content-Security-Policy", "default-src 'self'")
        .body("Current jwt user is " + encodedNickname);
}


}
