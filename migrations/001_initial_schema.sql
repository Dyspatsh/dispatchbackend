-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    username_hash VARCHAR(255) UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    recovery_phrase_hash TEXT NOT NULL,
    role VARCHAR(20) DEFAULT 'free' CHECK (role IN ('free', 'pro', 'premium')),
    is_banned BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP
);

-- Files table
CREATE TABLE files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
    recipient_id UUID REFERENCES users(id) ON DELETE CASCADE,
    encrypted_file_path TEXT NOT NULL,
    encrypted_session_key TEXT NOT NULL,
    encrypted_filename TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    custom_expiry_days INT,
    expires_at TIMESTAMP NOT NULL,
    pending_expires_at TIMESTAMP NOT NULL,
    downloaded BOOLEAN DEFAULT FALSE,
    cancelled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Messages table (Pro and Premium only)
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
    recipient_id UUID REFERENCES users(id) ON DELETE CASCADE,
    encrypted_content TEXT NOT NULL,
    is_deleted BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Active transfers tracking
CREATE TABLE active_transfers (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    transfer_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID REFERENCES files(id) ON DELETE CASCADE,
    started_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_users_username_hash ON users(username_hash);
CREATE INDEX idx_files_recipient_id ON files(recipient_id);
CREATE INDEX idx_files_expires_at ON files(expires_at);
CREATE INDEX idx_files_pending_expires_at ON files(pending_expires_at);
CREATE INDEX idx_messages_recipient_id ON messages(recipient_id);
CREATE INDEX idx_messages_expires_at ON messages(expires_at);
