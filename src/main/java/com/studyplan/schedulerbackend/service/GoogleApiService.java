package com.studyplan.schedulerbackend.service;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.services.calendar.Calendar;
import com.google.api.services.calendar.model.Event;
import com.google.api.services.calendar.model.EventDateTime;
import com.google.api.services.classroom.Classroom;
import com.google.api.services.classroom.model.Course;
import com.google.api.services.classroom.model.CourseWork;
import com.google.api.services.classroom.model.Date;
import com.studyplan.schedulerbackend.entity.Assignment;
import com.studyplan.schedulerbackend.entity.OAuth2Token;
import com.studyplan.schedulerbackend.entity.User;
import com.studyplan.schedulerbackend.entity.UserIdentity;
import com.studyplan.schedulerbackend.repository.AssignmentRepository;
import com.studyplan.schedulerbackend.repository.OAuth2TokenRepository;
import com.studyplan.schedulerbackend.repository.UserIdentityRepository;
import com.studyplan.schedulerbackend.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;

@Service
public class GoogleApiService {
    private static final Logger logger = LoggerFactory.getLogger(GoogleApiService.class);

    private final UserRepository userRepository;
    private final UserIdentityRepository identityRepository;
    private final OAuth2TokenRepository tokenRepository;
    private final AssignmentRepository assignmentRepository;
    private final String clientId;
    private final String clientSecret;
    private final String applicationName = "StudyPlanScheduler";

    public GoogleApiService(UserRepository userRepository,
                            UserIdentityRepository identityRepository,
                            OAuth2TokenRepository tokenRepository,
                            AssignmentRepository assignmentRepository,
                            @Value("${spring.security.oauth2.client.registration.google.client-id}") String clientId,
                            @Value("${spring.security.oauth2.client.registration.google.client-secret}") String clientSecret) {
        this.userRepository = userRepository;
        this.identityRepository = identityRepository;
        this.tokenRepository = tokenRepository;
        this.assignmentRepository = assignmentRepository;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        logger.debug("GoogleApiService initialized");
    }

    private Credential getCredential(Long userId, String provider) throws IOException, GeneralSecurityException {
        OAuth2Token token = tokenRepository.findByUserIdAndProvider(userId, provider)
                .orElseThrow(() -> new IllegalArgumentException("No token found for user id=" + userId + ", provider=" + provider));

        GoogleCredential credential = new GoogleCredential.Builder()
                .setTransport(GoogleNetHttpTransport.newTrustedTransport())
                .setJsonFactory(GsonFactory.getDefaultInstance())
                .setClientSecrets(clientId, clientSecret)
                .build()
                .setAccessToken(token.getAccessToken())
                .setRefreshToken(token.getRefreshToken())
                .setExpirationTimeMilliseconds(token.getExpiresAt() != null ? token.getExpiresAt().toEpochMilli() : null);

        if (credential.getExpiresInSeconds() != null && credential.getExpiresInSeconds() < 60) {
            logger.info("Access token expired for user id={}. Attempting to refresh.", userId);
            int retries = 3;
            while (retries-- > 0) {
                try {
                    if (credential.refreshToken()) {
                        token.setAccessToken(credential.getAccessToken());
                        token.setExpiresAt(Instant.ofEpochMilli(credential.getExpirationTimeMilliseconds()));
                        tokenRepository.save(token);
                        logger.info("Refreshed access token for user id={}", userId);
                        break;
                    } else {
                        throw new IOException("Failed to refresh access token");
                    }
                } catch (IOException e) {
                    if (retries == 0) {
                        logger.error("Failed to refresh token for user id={} after retries", userId, e);
                        throw e;
                    }
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted during token refresh", ie);
                    }
                }
            }
        }

        return credential;
    }

    private boolean hasIdentity(User user, String provider) {
        return user.getIdentities().stream()
                .anyMatch(identity -> provider.equals(identity.getProvider()));
    }

    private Classroom getClassroomService(Credential credential) throws IOException, GeneralSecurityException {
        return new Classroom.Builder(
                GoogleNetHttpTransport.newTrustedTransport(),
                GsonFactory.getDefaultInstance(),
                credential)
                .setApplicationName(applicationName)
                .build();
    }

    private Calendar getCalendarService(Credential credential) throws IOException, GeneralSecurityException {
        return new Calendar.Builder(
                GoogleNetHttpTransport.newTrustedTransport(),
                GsonFactory.getDefaultInstance(),
                credential)
                .setApplicationName(applicationName)
                .build();
    }

    public void createCalendarEvent(String email, String summary, Instant startTime) {
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new IllegalArgumentException("User not found: " + email));
            if (!hasIdentity(user, "google")) {
                throw new IllegalStateException("User is not authenticated with Google");
            }

            Credential credential = getCredential(user.getId(), "google");
            Calendar calendarService = getCalendarService(credential);

            Event event = new Event().setSummary(summary);
            EventDateTime start = new EventDateTime()
                    .setDateTime(new com.google.api.client.util.DateTime(startTime.toEpochMilli()))
                    .setTimeZone(ZoneId.systemDefault().getId());
            EventDateTime end = new EventDateTime()
                    .setDateTime(new com.google.api.client.util.DateTime(startTime.plusSeconds(3600).toEpochMilli()))
                    .setTimeZone(ZoneId.systemDefault().getId());
            event.setStart(start);
            event.setEnd(end);

            Event createdEvent = calendarService.events().insert("primary", event).execute();
            logger.info("Created calendar event for user: {}, eventId: {}", email, createdEvent.getId());
        } catch (IOException | GeneralSecurityException e) {
            logger.error("Failed to create calendar event for user: {}. Error: {}", email, e.getMessage(), e);
            throw new RuntimeException("Failed to create calendar event", e);
        }
    }

    public List<String> getClassroomCourses(String email) {
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new IllegalArgumentException("User not found: " + email));
            if (!hasIdentity(user, "google")) {
                throw new IllegalStateException("User is not authenticated with Google");
            }

            Credential credential = getCredential(user.getId(), "google");
            Classroom classroomService = getClassroomService(credential);

            List<Course> courses = classroomService.courses().list()
                    .setCourseStates(List.of("ACTIVE"))
                    .execute()
                    .getCourses();
            if (courses == null) courses = List.of();

            List<String> courseNames = new ArrayList<>();
            for (Course course : courses) {
                courseNames.add(course.getName() + " (" + course.getId() + ")");
            }

            logger.info("Retrieved {} courses for user: {}", courseNames.size(), email);
            return courseNames;
        } catch (IOException | GeneralSecurityException e) {
            logger.error("Failed to retrieve courses for user: {}. Error: {}", email, e.getMessage(), e);
            throw new RuntimeException("Failed to retrieve courses", e);
        }
    }

    @Scheduled(fixedRate = 3600000)
    public void syncClassroomAssignments() {
        List<User> users = userRepository.findAll();
        for (User user : users) {
            if (hasIdentity(user, "google")) {
                logger.debug("Syncing assignments for user: {}", user.getEmail());
                syncUserAssignments(user);
            }
        }
    }

    @Transactional
    protected void syncUserAssignments(User user) {
        try {
            Optional<OAuth2Token> tokenOpt = tokenRepository.findByUserIdAndProvider(user.getId(), "google");
            if (tokenOpt.isEmpty()) {
                logger.warn("No OAuth2 token for user: {}", user.getEmail());
                return;
            }

            Credential credential = getCredential(user.getId(), "google");
            Classroom classroomService = getClassroomService(credential);
            Calendar calendarService = getCalendarService(credential);

            List<Course> courses = classroomService.courses().list()
                    .setCourseStates(List.of("ACTIVE"))
                    .execute()
                    .getCourses();
            if (courses == null) courses = List.of();

            for (Course course : courses) {
                String courseId = course.getId();
                List<CourseWork> courseWorks = classroomService.courses().courseWork().list(courseId)
                        .setCourseWorkStates(List.of("PUBLISHED"))
                        .execute()
                        .getCourseWork();
                if (courseWorks == null) courseWorks = List.of();

                for (CourseWork work : courseWorks) {
                    String assignmentId = work.getId();
                    String title = work.getTitle();
                    Instant dueDate = null;

                    if (work.getDueDate() != null && work.getDueTime() != null) {
                        Date dueDateObj = work.getDueDate();
                        var timeObj = work.getDueTime();
                        ZonedDateTime dueDateTime = ZonedDateTime.of(
                                dueDateObj.getYear(),
                                dueDateObj.getMonth(),
                                dueDateObj.getDay(),
                                timeObj.getHours() != null ? timeObj.getHours() : 0,
                                timeObj.getMinutes() != null ? timeObj.getMinutes() : 0,
                                0,
                                0,
                                ZoneId.of("UTC"));
                        dueDate = dueDateTime.toInstant();
                    }

                    if (assignmentRepository.findByUserIdAndCourseIdAndAssignmentId(user.getId(), courseId, assignmentId).isEmpty()) {
                        Assignment assignment = new Assignment(user, courseId, assignmentId, title, dueDate);

                        if (dueDate != null) {
                            Event event = new Event().setSummary("Assignment Due: " + title);
                            event.setStart(new EventDateTime().setDateTime(new com.google.api.client.util.DateTime(dueDate.toEpochMilli())).setTimeZone(ZoneId.systemDefault().getId()));
                            event.setEnd(new EventDateTime().setDateTime(new com.google.api.client.util.DateTime(dueDate.plusSeconds(3600).toEpochMilli())).setTimeZone(ZoneId.systemDefault().getId()));
                            Event createdEvent = calendarService.events().insert("primary", event).execute();
                            assignment.setCalendarEventId(createdEvent.getId());
                            logger.info("Created calendar event for assignment: {}, user: {}", title, user.getEmail());
                        }

                        assignmentRepository.save(assignment);
                        logger.info("Saved new assignment: {}, course: {}, user: {}", title, courseId, user.getEmail());
                    }
                }
            }

            logger.info("Synced assignments for user: {}", user.getEmail());
        } catch (IOException | GeneralSecurityException e) {
            logger.error("Failed to sync assignments for user {}: {}", user.getEmail(), e.getMessage(), e);
        }
    }
}
