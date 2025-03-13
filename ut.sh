#!/bin/bash
# Create directories for test files
mkdir -p src/test/java/tech/robd/jwt/controller
mkdir -p src/test/java/tech/robd/jwt/util

# Create AuthControllerTest.java
cat << 'EOF' > src/test/java/tech/robd/jwt/controller/AuthControllerTest.java
package tech.robd.jwt.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@TestPropertySource(properties = {
    "app.username1.regex=^(user1|user2|user3)$",
    "app.username1.role=user",
    "app.username2.regex=^(admin1)$",
    "app.username2.role=admin",
    "app.passwordPrefix=",
    "app.passwordSuffix=pass"
})
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testMissingUsername() throws Exception {
        AuthRequest request = new AuthRequest("", "anyPassword");
        mockMvc.perform(post("/authenticate")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("Unauthorized: Username is required"));
    }

    @Test
    void testInvalidUsername() throws Exception {
        AuthRequest request = new AuthRequest("invalidUser", "invalidUserpass");
        mockMvc.perform(post("/authenticate")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("Unauthorized: Username is Invalid"));
    }

    @Test
    void testInvalidPassword() throws Exception {
        AuthRequest request = new AuthRequest("user1", "wrongPassword");
        mockMvc.perform(post("/authenticate")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("Unauthorized: Invalid password"));
    }

    @Test
    void testSuccessfulAuthentication() throws Exception {
        // For user1, a valid password is constructed as: passwordPrefix + "user1" + passwordSuffix, which is "user1pass"
        AuthRequest request = new AuthRequest("user1", "user1pass");
        mockMvc.perform(post("/authenticate")
                .contentType("application/json")
                .content(objectMapper.writeValueAsString(request)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").isNotEmpty());
    }
}
EOF

# Create JwtTokenUtilTest.java
cat << 'EOF' > src/test/java/tech/robd/jwt/util/JwtTokenUtilTest.java
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
EOF

echo "Unit test files have been created in src/test/java/tech/robd/jwt/controller and src/test/java/tech/robd/jwt/util."
