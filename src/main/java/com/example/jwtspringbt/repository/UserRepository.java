package com.example.jwtspringbt.repository;


import com.example.jwtspringbt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


    public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);  // Menambahkan method ini

    void deleteById(Integer id);

    Optional<User> findById(Integer id);

}