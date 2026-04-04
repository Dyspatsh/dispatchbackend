use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::Json,
    Json as AxumJson,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use std::collections::HashMap;

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

#[derive(Deserialize)]
pub struct PublicKeyUploadRequest {
    pub public_key: String,
}

#[derive(Serialize)]
pub struct PublicKeyUploadResponse {
    pub success: bool,
    pub message: String,
}

pub async fn search_users(
    Extension(pool): Extension<PgPool>,
    Query(query): Query<SearchQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    if query.q.len() < 2 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "success": false, "users": [] })));
    }
    
    let search_pattern = format!("%{}%", query.q);
    
    let users = sqlx::query!(
        "SELECT id, username FROM users WHERE username ILIKE $1 LIMIT 20",
        search_pattern
    )
    .fetch_all(&pool)
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

pub async fn get_public_key(
    Extension(pool): Extension<PgPool>,
    Query(params): Query<HashMap<String, String>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user_id = match params.get("user_id") {
        Some(id) => match Uuid::parse_str(id) {
            Ok(id) => id,
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "success": false }))),
        },
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "success": false }))),
    };
    
    let result = sqlx::query!("SELECT public_key FROM users WHERE id = $1", user_id)
        .fetch_optional(&pool)
        .await;
    
    match result {
        Ok(Some(row)) => (StatusCode::OK, Json(serde_json::json!({ "success": true, "public_key": row.public_key }))),
        _ => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "success": false }))),
    }
}

pub async fn check_user_status(
    Extension(pool): Extension<PgPool>,
    Path(username): Path<String>,
) -> (StatusCode, Json<UserStatusResponse>) {
    let user = sqlx::query!(
        "SELECT id, is_banned FROM users WHERE username = $1",
        username
    )
    .fetch_optional(&pool)
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

pub async fn upload_public_key(
    Extension(pool): Extension<PgPool>,
    user_id: Uuid,
    AxumJson(payload): AxumJson<PublicKeyUploadRequest>,
) -> (StatusCode, Json<PublicKeyUploadResponse>) {
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
            Json(PublicKeyUploadResponse {
                success: true,
                message: "Public key saved".to_string(),
            }),
        ),
        Err(e) => {
            eprintln!("Public key upload error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PublicKeyUploadResponse {
                    success: false,
                    message: "Failed to save public key".to_string(),
                }),
            )
        }
    }
}

pub async fn get_public_key_by_username(
    Extension(pool): Extension<PgPool>,
    Path(username): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let result = sqlx::query!(
        "SELECT public_key FROM users WHERE username = $1 AND is_banned = false",
        username
    )
    .fetch_optional(&pool)
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

