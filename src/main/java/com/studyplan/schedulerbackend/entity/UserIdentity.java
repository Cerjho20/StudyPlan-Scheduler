package com.studyplan.schedulerbackend.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "user_identities",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_provider_provider_id", columnNames = {"provider", "provider_id"})
        })
@Data
@NoArgsConstructor
public class UserIdentity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "provider", nullable = false)
    private String provider;

    @Column(name = "provider_id", nullable = false)
    private String providerId;
}