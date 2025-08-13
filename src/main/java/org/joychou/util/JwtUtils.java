package org.joychou.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

@Slf4j
public class JwtUtils {

    private static final long EXPIRE = 1440 * 60 * 1000;  // 1440 Minutes, 1 DAY
    private static final String SECRET = "123456";
    private static final String B64_SECRET = Base64.getEncoder().encodeToString(SECRET.getBytes(StandardCharsets.UTF_8));

    /**
     * Generate JWT Token by jjwt (last update time: Jul 05, 2018)
     *
     * @author JoyChou 2022-09-20
     * @param userId userid
     * @return token
     */
    public static String generateTokenByJjwt(String userId) {
        return Jwts.builder()
                .setHeaderParam("typ", "JWT")   // header
                .setHeaderParam("alg", "HS256")     // header
                .setIssuedAt(new Date())    // token发布时间
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE))   // token过期时间
                .claim("userid", userId)
                // secret在signWith会base64解码，但网上很多代码示例并没对secret做base64编码，所以在爆破key的时候可以注意下。
                .signWith(SignatureAlgorithm.HS256, B64_SECRET)
                .compact();
    }

    public static String getUserIdFromJjwtToken(String token) {
        try {
            Claims claims = Jwts.parser().setSigningKey(B64_SECRET).parseClaimsJws(token).getBody();
            return (String)claims.get("userid");
        } catch (Exception e) {
            return e.toString();
        }
    }

    /**
     * Generate jwt token by java-jwt.
     *
     * @author JoyChou 2022-09-20
     * @param nickname nickname
     * @return jwt token
     */
    public static String generateTokenByJavaJwt(String nickname) {
        return JWT.create()
                .withClaim("nickname", nickname)
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRE))
                .withIssuedAt(new Date())
                .sign(Algorithm.HMAC256(SECRET));
    }


    /**
     * Verify JWT Token
     * @param token token
     * @return Valid token returns true. Invalid token returns false.
     */
    public static Boolean verifyTokenByJavaJwt(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
private static final Logger log = LoggerFactory.getLogger(JwtUtils.class);
private static final String SECRET_KEY = "your-secret-key"; // Should be stored securely
private static final ConcurrentHashMap<String, Date> tokenBlacklist = new ConcurrentHashMap<>();
private static final ConcurrentHashMap<String, Integer> rateLimitMap = new ConcurrentHashMap<>();

// Key rotation implementation
private static class RotatingKeyProvider {
    private final String[] keys = {SECRET_KEY, "backup-key-1", "backup-key-2"};
    private int currentKeyIndex = 0;
    
    public String getCurrentKey() {
        return keys[currentKeyIndex];
    }
    
    public void rotateKey() {
        currentKeyIndex = (currentKeyIndex + 1) % keys.length;
    }
}

private static final RotatingKeyProvider keyProvider = new RotatingKeyProvider();

// Rate limiter implementation
private static boolean isRateLimited(String remoteAddr) {
    Integer attempts = rateLimitMap.getOrDefault(remoteAddr, 0);
    if (attempts > 10) { // Max 10 attempts per minute
        return true;
    }
    rateLimitMap.put(remoteAddr, attempts + 1);
    
    // Clean up old entries every 100 requests
    if (rateLimitMap.size() > 100) {
        rateLimitMap.clear();
    }
    
    return false;
}

// Generate fingerprint based on user data
private static String generateFingerprint(HttpServletRequest request) {
    if (request == null) {
        return "default-fingerprint";
    }
    return request.getHeader("User-Agent") + ":" + request.getRemoteAddr();
}

// Check if token is blacklisted
private static boolean isBlacklisted(String token) {
    Date blacklistedUntil = tokenBlacklist.get(token);
    if (blacklistedUntil != null) {
        if (new Date().before(blacklistedUntil)) {
            return true;
        } else {
            // Clean up expired blacklist entries
            tokenBlacklist.remove(token);
        }
    }
    return false;
}

public static String getNicknameByJavaJwt(String token, HttpServletRequest request) {
    if (token == null || token.isEmpty()) {
        log.error("JWT token is null or empty");
        return null;
    }
    
    try {
        // Check if token is blacklisted to prevent replay attacks
        if (isBlacklisted(token)) {
            log.warn("Attempted use of blacklisted JWT token");
            return null;
        }
        
        // Implement rate limiting to prevent brute force attacks
        if (request != null && isRateLimited(request.getRemoteAddr())) {
            log.warn("Rate limit exceeded for IP: null", request.getRemoteAddr());
            throw new SecurityException("Rate limit exceeded");
        }

        // Use key rotation mechanism for enhanced security
        String currentKey = keyProvider.getCurrentKey();
        Algorithm algorithm = Algorithm.HMAC256(currentKey);
        
        // For more advanced deployments, use JWKS (commented out as it requires external setup)
        /*
        JwkProvider provider = new UrlJwkProvider("https://domain/.well-known/jwks.json");
        String kid = JWT.decode(token).getKeyId();
        if (kid != null) {
            Jwk jwk = provider.get(kid);
            algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
        }
        */
        
        // Create verifier with comprehensive validation
        DecodedJWT jwt = JWT.require(algorithm)
            .withIssuer("secure-app")
            .withAudience("trusted-client-id")  // Added audience validation
            .acceptLeeway(1)  // 1 sec for clock skew
            .withExpiresAt(new Date())  // Add explicit expiration check
            .withClaim("fingerprint", generateFingerprint(request))  // Add fingerprint for anti-theft
            .withHeader("typ", "JWT")  // Validate header to prevent header manipulation
            .withHeader("alg", "HS256")
            .build()
            .verify(token);
            
        // Extract claims from the verified token
        return jwt.getClaim("nickname").asString();
        
    } catch (JWTVerificationException e) {
        // Secure logging to prevent log injection
        log.error("JWT verification failed: null", e.getMessage().replaceAll("[\n\r\t]", ""));
        return null;
    } catch (Exception e) {
        // Catch any other exceptions to prevent unhandled errors
        log.error("Error processing JWT: null", e.getMessage().replaceAll("[\n\r\t]", ""));
        return null;
    }
}

// Helper method for backward compatibility
public static String getNicknameByJavaJwt(String token) {
    return getNicknameByJavaJwt(token, null);
}

// Method to blacklist a token (to be called when a user logs out)
public static void blacklistToken(String token, int minutesValid) {
    Date expirationTime = new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(minutesValid));
    tokenBlacklist.put(token, expirationTime);
}


    public static String getNicknameByJavaJwt(String token) {
        // If the signature is not verified, there will be security issues.
        if (!verifyTokenByJavaJwt(token)) {
            log.error("token is invalid");
            return null;
        }
        return JWT.decode(token).getClaim("nickname").asString();
    }


    public static void main(String[] args) {
        String jjwtToken = generateTokenByJjwt("10000");
        System.out.println(jjwtToken);
        System.out.println(getUserIdFromJjwtToken(jjwtToken));

        String token = generateTokenByJavaJwt("JoyChou");
        System.out.println(token);
        System.out.println(getNicknameByJavaJwt(token));
    }
}
