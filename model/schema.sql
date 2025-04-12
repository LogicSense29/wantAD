CREATE TABLE user (
    user_id PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(25) UNIQUE NOT NULL,
    mobile VARCHAR(20) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    user_password TEXT NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE, -- Not verified initially
    created_at TIMESTAMP DEFAULT NOW(),
);