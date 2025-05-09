package com.studyplan.schedulerbackend.repository;

import com.studyplan.schedulerbackend.entity.Assignment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AssignmentRepository extends JpaRepository<Assignment, Long> {
    Optional<Assignment> findByUserIdAndCourseIdAndAssignmentId(Long userId, String courseId, String assignmentId);
    List<Assignment> findByUserId(Long userId);
}