package tech.robd.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class JwtTokenUtil {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenUtil.class);

    private static final long JWT_TOKEN_VALIDITY = 24 * 60 * 60; // 24 hours in seconds

    private static final SecretKey SECRET_KEY = loadSecretKeyFromFile();

    private static SecretKey loadSecretKeyFromFile() {
        try {
            // Define path to your key file - you can adjust this path as needed
            Path keyPath = Paths.get("config", "jwt-key.txt");

            var lines = Files.readAllLines(keyPath);
            var startIndex = !lines.isEmpty() && lines.getFirst().trim().startsWith("#") ? 1 : 0;

            var keyContent = lines.subList(startIndex, lines.size()).stream()
                    .map(line -> line.replaceAll("\\s+", ""))
                    .collect(Collectors.joining());

            logger.info("JWT secret key loaded from file successfully");

            return Keys.hmacShaKeyFor(Decoders.BASE64.decode(keyContent));
        } catch (IOException e) {
            throw new RuntimeException("Failed to load JWT secret key from file", e);
        }
    }

    public static String generateToken(String username, String role) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", role);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SECRET_KEY)
                .compact();
    }

    public static String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public static String getRoleFromToken(String token) {
        return getClaimFromToken(token, claims -> claims.get("role", String.class));
    }

    public static Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public static <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private static Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public static Boolean validateToken(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    private static Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }
}
