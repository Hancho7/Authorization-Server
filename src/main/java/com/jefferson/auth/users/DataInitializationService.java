package com.jefferson.auth.users;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class DataInitializationService implements CommandLineRunner {

    private final com.jefferson.auth.users.UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public DataInitializationService(com.jefferson.auth.users.UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        createDefaultUsers();
    }

    private void createDefaultUsers() {
        // Create admin user
        if (!userRepository.existsByUsername("admin")) {
            com.jefferson.auth.users.User admin = new com.jefferson.auth.users.User("admin", "admin@example.com",
                    passwordEncoder.encode("admin123"), "Admin", "User");
            admin.setRoles(Set.of("ADMIN", "USER"));
            userRepository.save(admin);
            System.out.println("Default admin user created - Username: admin, Password: admin123");
        }

        // Create regular user
        if (!userRepository.existsByUsername("user")) {
            com.jefferson.auth.users.User user = new com.jefferson.auth.users.User("user", "user@example.com",
                    passwordEncoder.encode("user123"), "Regular", "User");
            user.setRoles(Set.of("USER"));
            userRepository.save(user);
            System.out.println("Default regular user created - Username: user, Password: user123");
        }

        // Create test user for development
        if (!userRepository.existsByUsername("testuser")) {
            com.jefferson.auth.users.User testUser = new com.jefferson.auth.users.User("testuser", "test@example.com",
                    passwordEncoder.encode("test123"), "Test", "User");
            testUser.setRoles(Set.of("USER"));
            testUser.setPhoneNumber("+1234567890");
            userRepository.save(testUser);
            System.out.println("Test user created - Username: testuser, Password: test123");
        }
    }
}

