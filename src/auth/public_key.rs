use axum::{extract::Extension, http::StatusCode, response::Json, Json as AxumJson};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app_state::AppState;

#[derive(Deserialize)]
pub struct UploadPublicKeyRequest {
    pub public_key: String,
}

#[derive(Serialize)]
pub struct UploadPublicKeyResponse {
    pub success: bool,
    pub message: String,
}

const MAX_PUBLIC_KEY_SIZE: usize = 4096; // 4KB limit for public keys

pub async fn upload_public_key(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<Uuid>,
    AxumJson(payload): AxumJson<UploadPublicKeyRequest>,
) -> (StatusCode, Json<UploadPublicKeyResponse>) {
    // Check size limit
    if payload.public_key.len() > MAX_PUBLIC_KEY_SIZE {
        return (
            StatusCode::BAD_REQUEST,
            Json(UploadPublicKeyResponse {
                success: false,
                message: format!("Public key too large. Maximum {} characters", MAX_PUBLIC_KEY_SIZE),
            }),
        );
    }
    
    // Validate it's a non-empty string
    if payload.public_key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(UploadPublicKeyResponse {
                success: false,
                message: "Public key cannot be empty".to_string(),
            }),
        );
    }
    
    // Optional: Validate XML structure (basic check)
    if !payload.public_key.trim().starts_with("<?xml") && !payload.public_key.trim().starts_with("<RSAKey") {
        // Log warning but still accept (some valid keys might not have XML header)
        tracing::warn!("Public key doesn't look like XML: {}", &payload.public_key[..payload.public_key.len().min(50)]);
    }
    
    // Update user's public key
    let result = sqlx::query!(
        "UPDATE users SET public_key = $1 WHERE id = $2",
        payload.public_key,
        user_id
    )
    .execute(&state.pool)
    .await;
    
    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(UploadPublicKeyResponse {
                success: true,
                message: "Public key uploaded successfully".to_string(),
            }),
        ),
        Err(e) => {
            eprintln!("Public key upload error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UploadPublicKeyResponse {
                    success: false,
                    message: "Failed to upload public key".to_string(),
                }),
            )
        }
    }
}
