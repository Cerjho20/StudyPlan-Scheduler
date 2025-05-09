package com.studyplan.schedulerbackend.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "assignments")
@Data
@NoArgsConstructor
public class Assignment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "course_id", nullable = false)
    private String courseId;

    @Column(name = "assignment_id", nullable = false)
    private String assignmentId;

    @Column(name = "title", nullable = false)
    private String title;

    @Column(name = "due_date")
    private Instant dueDate;

    @Column(name = "calendar_event_id")
    private String calendarEventId;

    public Assignment(User user, String courseId, String assignmentId, String title, Instant dueDate) {
        this.user = user;
        this.courseId = courseId;
        this.assignmentId = assignmentId;
        this.title = title;
        this.dueDate = dueDate;
    }
}