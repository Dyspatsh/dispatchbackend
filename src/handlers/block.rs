use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::Json,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

pub async fn block_user(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
    Path(username): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let target_user = sqlx::query!(
        "SELECT id FROM users WHERE username = $1",
        username
    )
    .fetch_optional(&pool)
    .await;
    
    let target_id = match target_user {
        Ok(Some(u)) => u.id,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "success": false, "message": "User not found" })),
            );
        }
    };
    
    if target_id == user_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "success": false, "message": "Cannot block yourself" })),
        );
    }
    
    let result = sqlx::query!(
        "INSERT INTO blocked_users (user_id, blocked_user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        user_id,
        target_id
    )
    .execute(&pool)
    .await;
    
    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "success": true, "message": "User blocked" })),
        ),
        Err(e) => {
            eprintln!("Block error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "message": "Failed to block user" })),
            )
        }
    }
}

pub async fn unblock_user(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
    Path(username): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let target_user = sqlx::query!(
        "SELECT id FROM users WHERE username = $1",
        username
    )
    .fetch_optional(&pool)
    .await;
    
    let target_id = match target_user {
        Ok(Some(u)) => u.id,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "success": false, "message": "User not found" })),
            );
        }
    };
    
    let result = sqlx::query!(
        "DELETE FROM blocked_users WHERE user_id = $1 AND blocked_user_id = $2",
        user_id,
        target_id
    )
    .execute(&pool)
    .await;
    
    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "success": true, "message": "User unblocked" })),
        ),
        Err(e) => {
            eprintln!("Unblock error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "message": "Failed to unblock user" })),
            )
        }
    }
}

pub async fn get_blocked_users(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    let blocked = sqlx::query!(
        "SELECT u.username FROM blocked_users b JOIN users u ON b.blocked_user_id = u.id WHERE b.user_id = $1",
        user_id
    )
    .fetch_all(&pool)
    .await;
    
    match blocked {
        Ok(rows) => {
            let usernames: Vec<String> = rows.into_iter().map(|r| r.username).collect();
            (
                StatusCode::OK,
                Json(json!({ "success": true, "blocked": usernames })),
            )
        }
        Err(e) => {
            eprintln!("Get blocked error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "success": false, "message": "Failed to get blocked users" })),
            )
        }
    }
}

pub async fn is_blocked_by(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
    Path(username): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let target_user = sqlx::query!(
        "SELECT id FROM users WHERE username = $1",
        username
    )
    .fetch_optional(&pool)
    .await;
    
    let target_id = match target_user {
        Ok(Some(u)) => u.id,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "is_blocked": false })),
            );
        }
    };
    
    let is_blocked = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM blocked_users WHERE user_id = $1 AND blocked_user_id = $2)",
        target_id,
        user_id
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(Some(false))
    .unwrap_or(false);
    
    (StatusCode::OK, Json(json!({ "is_blocked": is_blocked })))
}
