CREATE TABLE user_profiles (
    user_id UUID PRIMARY KEY,
    display_name VARCHAR(100) NOT NULL,
    bio VARCHAR(500) NOT NULL,
    locale VARCHAR(35) NOT NULL,
    time_zone VARCHAR(64) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    version BIGINT NOT NULL DEFAULT 0
);
