use axum::{extract::Extension, http::StatusCode, response::Json, Json as AxumJson};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct UploadPublicKeyRequest {
    pub public_key: String,
}

#[derive(Serialize)]
pub struct UploadPublicKeyResponse {
    pub success: bool,
    pub message: String,
}

pub async fn upload_public_key(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
    AxumJson(payload): AxumJson<UploadPublicKeyRequest>,
) -> (StatusCode, Json<UploadPublicKeyResponse>) {
    // Accept any non-empty public key (will accept real XML)
    if payload.public_key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(UploadPublicKeyResponse {
                success: false,
                message: "Public key cannot be empty".to_string(),
            }),
        );
    }
    
    // Update user's public key
    let result = sqlx::query!(
        "UPDATE users SET public_key = $1 WHERE id = $2",
        payload.public_key,
        user_id
    )
    .execute(&pool)
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
