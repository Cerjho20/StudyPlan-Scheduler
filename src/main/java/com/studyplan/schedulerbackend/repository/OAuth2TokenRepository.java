package com.studyplan.schedulerbackend.repository;

import com.studyplan.schedulerbackend.entity.OAuth2Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuth2TokenRepository extends JpaRepository<OAuth2Token, Long> {
  Optional<OAuth2Token> findByUserIdAndProvider(Long userId, String provider);
}