package com.example.jwtspringbt.service;


import com.example.jwtspringbt.DTO.UserDTO;
import com.example.jwtspringbt.model.User;
import com.example.jwtspringbt.repository.UserRepository;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.stereotype.Service;

import java.sql.Connection;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserService {




        private final UserRepository userRepository;
        private final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
        private Object dataSource;

        public UserService(UserRepository userRepository) {
            this.userRepository = userRepository;
            this.dataSource = dataSource;
        }



            public List<UserDTO> getAllUsers() {
                List<User> users = userRepository.findAll();

                return users.stream()
                        .map(this::convertToDTO) // Convert User to UserDTO
                        .collect(Collectors.toList());
            }

            public UserDTO getUserById(Integer id) {
                return userRepository.findById(id)
                        .map(this::convertToDTO)
                        .orElse(null);
            }


                public User createUser(User user) {
                    user.setCreatedAt(LocalDateTime.now()); // Set createdAt saat membuat pengguna baru
                    return userRepository.save(user);
                }

                public User updateUser(Integer id, User user) {
                    User existingUser = userRepository.findById(id).orElse(null);
                    if (existingUser != null) {
                        existingUser.setFirstName(user.getFirstName());
                        existingUser.setLastName(user.getLastName());
                        existingUser.setUsername(user.getUsername());
                        existingUser.setEmail(user.getEmail());
                        existingUser.setPassword(user.getPassword()); // Ideally, password should be encoded
                        existingUser.setRole(user.getRole());
                        return userRepository.save(existingUser);
                    }
                    return null;
                }
                public void deleteUser(Integer id) {
                    userRepository.deleteById(id);
                }

                public void deleteAllUsers() {
                    userRepository.deleteAll();
                }

                private UserDTO convertToDTO(User user) {
                    UserDTO userDTO = new UserDTO();
                    userDTO.setId(user.getId());
                    userDTO.setFirstName(user.getFirstName());
                    userDTO.setLastName(user.getLastName());
                    userDTO.setUsername(user.getUsername());
                    userDTO.setEmail(user.getEmail());
                    if (user.getRole() != null) {
                        userDTO.setRole(user.getRole().name()); // Jika role adalah enum
                    } else {
                        userDTO.setRole("USER"); // Atau value default lainnya
                    }

                    if (user.getCreatedAt() != null) {
                        userDTO.setCreatedAt(user.getCreatedAt().format(formatter)); // Sesuaikan format formatter dengan yang diharapkan
                    } else {
                        userDTO.setCreatedAt(null);
                    }
                    return userDTO;
                }
                public UserDTO getUserDTOById(Integer id) {
                    User user = userRepository.findById(id).orElse(null);
                    if (user != null) {
                        return convertToDTO(user);
                    } else {
                        return null;
                    }
                }

                public void resetUserTable() {
                    HikariDataSource dataSource = new HikariDataSource();
                    try (Connection connection = dataSource.getConnection();
                         Statement statement = connection.createStatement()) {
                        // Untuk MySQL
                        statement.execute("TRUNCATE TABLE user");

                        // Untuk PostgreSQL
                        // statement.execute("TRUNCATE TABLE user RESTART IDENTITY");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

            }