use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileRecord {
    pub id: Uuid,
    pub sender_id: Uuid,
    pub recipient_id: Uuid,
    pub filename: String,
    pub file_size: i64,
    pub expires_at: DateTime<Utc>,
}
