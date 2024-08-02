package com.example.jwtspringbt.controller;

import com.example.jwtspringbt.model.AuthenticationResponse;
import com.example.jwtspringbt.model.User;
import com.example.jwtspringbt.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*")
public class AuthenticationController {

    private final AuthenticationService authService;

    public AuthenticationController(AuthenticationService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody User request
    ) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @RequestBody User request
    ) {
        // Panggil metode authenticate dengan parameter yang sesuai
        return ResponseEntity.ok(authService.authenticate(request.getUsername(), request.getPassword()));
    }
}
