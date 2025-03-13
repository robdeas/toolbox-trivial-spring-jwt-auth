package tech.robd.jwt.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class JwtTokenUtilTest {

    @Test
    void testGenerateAndValidateToken() {
        String username = "user1";
        String role = "user";
        String token = JwtTokenUtil.generateToken(username, role);
        assertNotNull(token, "Token should not be null");
        assertTrue(JwtTokenUtil.validateToken(token), "Token should be valid");
        assertEquals(username, JwtTokenUtil.getUsernameFromToken(token), "Username should match");
        assertEquals(role, JwtTokenUtil.getRoleFromToken(token), "Role should match");
    }
}
