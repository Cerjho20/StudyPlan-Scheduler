-- db/migration/V2__create_user_identities.sql

CREATE TABLE user_identities (
                                 id BIGINT AUTO_INCREMENT PRIMARY KEY,
                                 user_id BIGINT NOT NULL,
                                 provider VARCHAR(255) NOT NULL,
                                 provider_id VARCHAR(255) NOT NULL,
                                 created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                 CONSTRAINT uk_provider_provider_id UNIQUE (provider, provider_id),
                                 CONSTRAINT fk_user_identities_user FOREIGN KEY (user_id)
                                     REFERENCES users(id)
                                     ON DELETE CASCADE
);
