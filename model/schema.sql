CREATE TABLE user (
    user_id PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(25) UNIQUE NOT NULL,
    mobile VARCHAR(20) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    user_password TEXT NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE, -- Not verified initially
    created_at TIMESTAMP DEFAULT NOW(),
);

CREATE TABLE otp_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp TEXT NOT NULL,  -- Temporary OTP storage
    otp_expires_at TIMESTAMP NOT NULL, -- Expiry time
    created_at TIMESTAMP DEFAULT NOW()
);