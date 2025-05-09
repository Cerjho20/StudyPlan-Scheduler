package com.studyplan.schedulerbackend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users",  // renamed to avoid reserved keywords
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_provider_providerId", columnNames = {"provider", "provider_id"})
        })
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String email;

    @Column
    private String password;

    @Column(nullable = false)
    private String provider;

    @Column(name = "provider_id")
    private String providerId; // nullable for traditional e.g., Google ID, Facebook ID

    @Column(nullable = false)
    private String role; // e.g., "USER", "ADMIN"
}
