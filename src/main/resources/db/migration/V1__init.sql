CREATE TABLE users (
                       id BIGINT AUTO_INCREMENT PRIMARY KEY,
                       email VARCHAR(255) NOT NULL,
                       password VARCHAR(255),
                       role VARCHAR(255) NOT NULL,
                       CONSTRAINT uk_email UNIQUE (email)
);


CREATE TABLE assignments (
                             id BIGINT AUTO_INCREMENT PRIMARY KEY,
                             user_id BIGINT NOT NULL,
                             course_id VARCHAR(255) NOT NULL,
                             assignment_id VARCHAR(255) NOT NULL,
                             title VARCHAR(255) NOT NULL,
                             due_date DATETIME,
                             calendar_event_id VARCHAR(255),
                             FOREIGN KEY (user_id) REFERENCES users(id),
                             UNIQUE (user_id, course_id, assignment_id)
);

CREATE TABLE oauth2_tokens (
                               id BIGINT AUTO_INCREMENT PRIMARY KEY,
                               user_id BIGINT NOT NULL,
                               provider VARCHAR(255) NOT NULL,
                               access_token TEXT NOT NULL,
                               refresh_token TEXT,
                               expires_at DATETIME,
                               FOREIGN KEY (user_id) REFERENCES users(id),
                               UNIQUE (user_id, provider)
);

CREATE TABLE password_reset_token (
                                      id BIGINT AUTO_INCREMENT PRIMARY KEY,
                                      token VARCHAR(255) NOT NULL UNIQUE,
                                      user_id BIGINT NOT NULL,
                                      expiry_date DATETIME NOT NULL,
                                      FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE oauth2_authorized_client (
                                          client_registration_id VARCHAR(100) NOT NULL,
                                          principal_name VARCHAR(200) NOT NULL,
                                          access_token_type VARCHAR(100) NOT NULL,
                                          access_token_value BLOB NOT NULL,
                                          access_token_issued_at TIMESTAMP NOT NULL,
                                          access_token_expires_at TIMESTAMP NULL, -- Changed to NULL to avoid default value issue
                                          access_token_scopes VARCHAR(1000),
                                          refresh_token_value BLOB,
                                          refresh_token_issued_at TIMESTAMP NULL, -- Changed to NULL
                                          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                                          PRIMARY KEY (client_registration_id, principal_name)
);