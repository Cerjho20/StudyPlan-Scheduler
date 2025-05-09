// src/main/java/com/studyplan/schedulerbackend/repository/UserIdentityRepository.java
package com.studyplan.schedulerbackend.repository;

import com.studyplan.schedulerbackend.entity.UserIdentity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserIdentityRepository extends JpaRepository<UserIdentity, Long> {
    /**
     * Look up an identity by OAuth provider name and provider-specific ID.
     */
    Optional<UserIdentity> findByProviderAndProviderId(String provider, String providerId);
}
