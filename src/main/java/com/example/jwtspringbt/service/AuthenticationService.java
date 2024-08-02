package com.example.jwtspringbt.service;

import com.example.jwtspringbt.model.AuthenticationResponse;
import com.example.jwtspringbt.model.Role;
import com.example.jwtspringbt.model.Token;
import com.example.jwtspringbt.model.User;
import com.example.jwtspringbt.repository.TokenRepository;
import com.example.jwtspringbt.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TokenRepository tokenRepository;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository repository,
                                 PasswordEncoder passwordEncoder,
                                 JwtService jwtService,
                                 TokenRepository tokenRepository,
                                 AuthenticationManager authenticationManager) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.tokenRepository = tokenRepository;
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationResponse register(User request) {
        // Validate input
        if (request.getUsername() == null || request.getEmail() == null || request.getPassword() == null) {
            return new AuthenticationResponse(null, "Invalid input");
        }

        // Check if user already exists by username or email
        if (repository.findByUsername(request.getUsername()).isPresent() ||
                repository.findByEmail(request.getEmail()).isPresent()) {
            return new AuthenticationResponse(null, "User already exists");
        }

        // Create new user
        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());  // Set email
        user.setRole(request.getRole() != null ? request.getRole() : Role.valueOf("USER")); // Default to "USER" if role is null
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        // Save user and generate JWT
        user = repository.save(user);
        String jwt = jwtService.generateToken(user);
        saveUserToken(jwt, user);

        return new AuthenticationResponse(jwt, "User registration was successful");
    }

    public AuthenticationResponse authenticate(String identifier, String password) {
        // Validate input
        if (identifier == null || password == null) {
            return new AuthenticationResponse(null, "Invalid input");
        }

        // Allow authentication by username or email
        Optional<User> userOpt = repository.findByUsername(identifier);
        if (userOpt.isEmpty()) {
            userOpt = repository.findByEmail(identifier);
        }

        User user = userOpt.orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Authenticate user
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), password)
        );

        // Generate JWT and handle tokens
        String jwt = jwtService.generateToken(user);
        revokeAllTokenByUser(user);
        saveUserToken(jwt, user);

        return new AuthenticationResponse(jwt, "User login was successful");
    }

    private void revokeAllTokenByUser(User user) {
        List<Token> validTokens = tokenRepository.findAllTokensByUser(user.getId());
        if (!validTokens.isEmpty()) {
            validTokens.forEach(t -> t.setLoggedOut(true));
            tokenRepository.saveAll(validTokens);
        }
    }

    private void saveUserToken(String jwt, User user) {
        Token token = new Token();
        token.setToken(jwt);
        token.setLoggedOut(false);
        token.setUser(user);
        tokenRepository.save(token);
    }
}
