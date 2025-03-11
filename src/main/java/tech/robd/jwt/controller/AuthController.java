package tech.robd.jwt.controller;

import tech.robd.jwt.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthController {

    @Value("${app.username.regex}")
    private String usernameRegex;

    @Value("${app.passwordPrefix}")
    private String passwordPrefix;

    @Value("${app.passwordSuffix}")
    private String passwordSuffix;


    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthRequest authRequest) {
        // Check if username is missing or blank
        if (authRequest.username() == null || authRequest.username().trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Unauthorized: Username is required"));
        }

        // Check if username matches the regex from the config file
        if (!authRequest.username().matches(usernameRegex)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Unauthorized: Username is Invalid"));
        }

        // Check if password does not end with "pass"
        if (authRequest.password() == null || !authRequest.password().equals(passwordPrefix + authRequest.username() + passwordSuffix )) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Unauthorized: Invalid password"));
        }

        // Generate a token based on the provided username
        String token = JwtTokenUtil.generateToken(authRequest.username());
        return ResponseEntity.ok(new AuthResponse(token));
    }
}
