/*
 * Copyright (c) 2025 Robert Deas
 *
 * This file is dual-licensed under the MIT License and the Apache License, Version 2.0.
 * You may choose either license to govern your use of this file.
 *
 * MIT License:
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   [Insert full MIT license text or refer to a LICENSE file]
 *
 * Apache License, Version 2.0:
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at:
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
package tech.robd.jwt.controller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tech.robd.jwt.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

@RestController
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Value("${app.username1.regex:}")
    private Optional<String> username1Regex;

    @Value("${app.username1.role:}")
    private Optional<String> username1Role;

    @Value("${app.username2.regex:}")
    private Optional<String> username2Regex;

    @Value("${app.username2.role:}")
    private Optional<String> username2Role;

    @Value("${app.username3.regex:}")
    private Optional<String> username3Regex;

    @Value("${app.username3.role:}")
    private Optional<String> username3Role;

    @Value("${app.username4.regex:}")
    private Optional<String> username4Regex;

    @Value("${app.username4.role:}")
    private Optional<String> username4Role;


    @Value("${app.passwordPrefix}")
    private String passwordPrefix;

    @Value("${app.passwordSuffix}")
    private String passwordSuffix;




    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthRequest authRequest) {
        logger.info("Authentication request received for username: {}", authRequest.username());
        // Check if username is missing or blank
        if (authRequest.username() == null || authRequest.username().trim().isEmpty()) {
            logger.warn("Authentication failed: username is missing");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Unauthorized: Username is required"));
        }

        AtomicReference<String> roleRef = new AtomicReference<>("");
        AtomicBoolean isUsernameFound = new AtomicBoolean(false);

        username1Regex.ifPresent(regex -> {
            if (authRequest.username().matches(regex)) {
                isUsernameFound.set(true);
                roleRef.set(username1Role.orElse(""));
            }
         });

        username2Regex.ifPresent(regex -> {
            if (authRequest.username().matches(regex)) {
                isUsernameFound.set(true);
                roleRef.set(username2Role.orElse(""));
            }
        });

        username3Regex.ifPresent(regex -> {
            if (authRequest.username().matches(regex)) {
                isUsernameFound.set(true);
                roleRef.set(username3Role.orElse(""));
            }
        });

        username4Regex.ifPresent(regex -> {
            if (authRequest.username().matches(regex)) {
                isUsernameFound.set(true);
                roleRef.set(username4Role.orElse(""));
            }
        });


        String role = roleRef.get();

        // Check if username matches the regex from the config file
        if (!isUsernameFound.get()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Unauthorized: Username is Invalid"));
        }

        // Check if password does not end with "pass"
        if (authRequest.password() == null || !authRequest.password().equals(passwordPrefix + authRequest.username() + passwordSuffix )) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponse("Unauthorized: Invalid password"));
        }

        // Generate a token based on the provided username
        String token = JwtTokenUtil.generateToken(authRequest.username(), role);
        logger.info("Authentication successful for user '{}'", authRequest.username());
        return ResponseEntity.ok(new AuthResponse(token));
    }
}
