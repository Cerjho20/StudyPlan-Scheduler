package com.studyplan.schedulerbackend.repository;

import com.studyplan.schedulerbackend.entity.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    /**
     * Look up a user by email (for standard login).
     */
    Optional<User> findByEmail(
            @NotBlank(message = "Email is required")
            @Email(message = "Invalid email format")
            String email
    );
}