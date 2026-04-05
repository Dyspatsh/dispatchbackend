use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::app_state::AppState;

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
}

#[derive(Serialize)]
pub struct UserResult {
    pub username: String,
    pub user_id: Uuid,
}

#[derive(Serialize)]
pub struct UserStatusResponse {
    pub success: bool,
    pub exists: bool,
    pub is_banned: bool,
    pub message: String,
}

pub async fn search_users(
    Extension(state): Extension<AppState>,
    Query(query): Query<SearchQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    if query.q.len() < 2 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "success": false, "users": [] })));
    }
    
    // Escape special characters in LIKE pattern to prevent injection
    let search_term = query.q.replace("%", "\\%").replace("_", "\\_");
    let search_pattern = format!("%{}%", search_term);
    
    let users = sqlx::query!(
        "SELECT id, username FROM users WHERE username ILIKE $1 AND is_banned = false LIMIT 20",
        search_pattern
    )
    .fetch_all(&state.pool)
    .await;
    
    match users {
        Ok(rows) => {
            let results: Vec<UserResult> = rows.into_iter()
                .map(|row| UserResult { username: row.username, user_id: row.id })
                .collect();
            (StatusCode::OK, Json(serde_json::json!({ "success": true, "users": results })))
        }
        Err(e) => {
            eprintln!("Search error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "success": false, "users": [] })))
        }
    }
}

pub async fn check_user_status(
    Extension(state): Extension<AppState>,
    Path(username): Path<String>,
) -> (StatusCode, Json<UserStatusResponse>) {
    let user = sqlx::query!(
        "SELECT id, is_banned FROM users WHERE username = $1",
        username
    )
    .fetch_optional(&state.pool)
    .await;
    
    match user {
        Ok(Some(u)) => {
            if u.is_banned.unwrap_or(false) {
                (
                    StatusCode::OK,
                    Json(UserStatusResponse {
                        success: true,
                        exists: true,
                        is_banned: true,
                        message: "User is banned".to_string(),
                    }),
                )
            } else {
                (
                    StatusCode::OK,
                    Json(UserStatusResponse {
                        success: true,
                        exists: true,
                        is_banned: false,
                        message: "User exists and is active".to_string(),
                    }),
                )
            }
        }
        Ok(None) => (
            StatusCode::OK,
            Json(UserStatusResponse {
                success: true,
                exists: false,
                is_banned: false,
                message: "User not found".to_string(),
            }),
        ),
        Err(e) => {
            eprintln!("Status check error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UserStatusResponse {
                    success: false,
                    exists: false,
                    is_banned: false,
                    message: "Database error".to_string(),
                }),
            )
        }
    }
}

pub async fn get_public_key_by_username(
    Extension(state): Extension<AppState>,
    Path(username): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let result = sqlx::query!(
        "SELECT public_key FROM users WHERE username = $1 AND is_banned = false",
        username
    )
    .fetch_optional(&state.pool)
    .await;
    
    match result {
        Ok(Some(row)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "public_key": row.public_key
            })),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "success": false,
                "message": "User not found or banned"
            })),
        ),
        Err(e) => {
            eprintln!("Get public key error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "message": "Database error"
                })),
            )
        }
    }
}
