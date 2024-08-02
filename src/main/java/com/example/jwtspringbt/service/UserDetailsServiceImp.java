package com.example.jwtspringbt.service;

import com.example.jwtspringbt.model.User;
import com.example.jwtspringbt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserDetailsServiceImp implements UserDetailsService {

    private final UserRepository repository;

    public UserDetailsServiceImp(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String identifier) throws UsernameNotFoundException {
        // Cari user berdasarkan username atau email
        Optional<User> userOpt = repository.findByUsername(identifier);
        if (userOpt.isEmpty()) {
            userOpt = repository.findByEmail(identifier);
        }

        User user = userOpt.orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // Return user as UserDetails
        return user;
    }
}
