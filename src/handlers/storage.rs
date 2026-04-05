use axum::{extract::Extension, http::StatusCode, response::Json};
use serde_json::json;
use uuid::Uuid;

use crate::app_state::AppState;

pub async fn get_storage_info(
    Extension(state): Extension<AppState>,
    Extension(user_id): Extension<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    let result = sqlx::query!(
        "SELECT storage_used_mb, storage_limit_mb FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(&state.pool)
    .await;

    match result {
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "used_mb": row.storage_used_mb.unwrap_or(0),
                "limit_mb": row.storage_limit_mb.unwrap_or(1024),
                "remaining_mb": (row.storage_limit_mb.unwrap_or(1024) - row.storage_used_mb.unwrap_or(0))
            })),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "message": "User not found"
            })),
        ),
        Err(e) => {
            eprintln!("Storage info error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "success": false,
                    "message": "Failed to get storage info"
                })),
            )
        }
    }
}
