use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::Json,
    Json as AxumJson,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use chrono::{Utc, Duration};
use std::path::PathBuf;
use tokio::fs;

const STORAGE_PATH: &str = "/opt/dispatch/storage/files";

#[derive(Deserialize)]
pub struct UploadRequest {
    pub recipient_username: String,
    pub encrypted_data: String,
    pub encrypted_session_key: String,
    pub encrypted_filename: String,
    pub custom_expiry_days: Option<i32>,
}

#[derive(Serialize)]
pub struct UploadResponse {
    pub success: bool,
    pub message: String,
    pub file_id: Option<Uuid>,
}

// Check if user A has blocked user B
async fn is_blocked(pool: &PgPool, user_a_id: Uuid, user_b_id: Uuid) -> bool {
    let result = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM blocked_users WHERE user_id = $1 AND blocked_user_id = $2)",
        user_a_id,
        user_b_id
    )
    .fetch_one(pool)
    .await;
    
    result.unwrap_or(Some(false)).unwrap_or(false)
}

pub async fn upload_file(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
    AxumJson(payload): AxumJson<UploadRequest>,
) -> (StatusCode, Json<UploadResponse>) {
    // Find recipient
    let recipient = sqlx::query!(
        "SELECT id FROM users WHERE username = $1",
        payload.recipient_username
    )
    .fetch_optional(&pool)
    .await;
    
    let recipient_id = match recipient {
        Ok(Some(r)) => r.id,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(UploadResponse {
                    success: false,
                    message: "Recipient not found".to_string(),
                    file_id: None,
                }),
            );
        }
    };
    
    // Check if sender is blocked by recipient
    if is_blocked(&pool, recipient_id, user_id).await {
        return (
            StatusCode::FORBIDDEN,
            Json(UploadResponse {
                success: false,
                message: "This user has blocked you".to_string(),
                file_id: None,
            }),
        );
    }
    
    // Check if recipient is blocked by sender
    if is_blocked(&pool, user_id, recipient_id).await {
        return (
            StatusCode::FORBIDDEN,
            Json(UploadResponse {
                success: false,
                message: "You have blocked this user".to_string(),
                file_id: None,
            }),
        );
    }
    
    let file_id = Uuid::new_v4();
    let file_path = format!("{}/{}.bin", STORAGE_PATH, file_id);
    
    use base64::Engine;
    let file_data = match base64::engine::general_purpose::STANDARD.decode(&payload.encrypted_data) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(UploadResponse {
                    success: false,
                    message: format!("Invalid base64 data: {}", e),
                    file_id: None,
                }),
            );
        }
    };
    
    if let Some(parent) = PathBuf::from(&file_path).parent() {
        let _ = fs::create_dir_all(parent).await;
    }
    
    if let Err(e) = fs::write(&file_path, file_data).await {
        eprintln!("Write error: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(UploadResponse {
                success: false,
                message: format!("Failed to save file: {}", e),
                file_id: None,
            }),
        );
    }
    
    let custom_days = payload.custom_expiry_days.unwrap_or(7).clamp(1, 7);
    let expires_at = Utc::now() + Duration::days(custom_days as i64);
    let pending_expires_at = Utc::now() + Duration::days(3);
    let expires_at_naive = expires_at.naive_utc();
    let pending_expires_at_naive = pending_expires_at.naive_utc();
    
    let _result = sqlx::query!(
        "INSERT INTO files (id, sender_id, recipient_id, encrypted_file_path, encrypted_session_key, 
         encrypted_filename, file_size, custom_expiry_days, expires_at, pending_expires_at, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending')",
        file_id,
        user_id,
        recipient_id,
        file_path,
        payload.encrypted_session_key,
        payload.encrypted_filename,
        payload.encrypted_data.len() as i64,
        custom_days,
        expires_at_naive,
        pending_expires_at_naive
    )
    .execute(&pool)
    .await;
    
    match _result {
        Ok(_) => {
            println!("File saved: {} from {} to {}", file_id, user_id, recipient_id);
            (
                StatusCode::OK,
                Json(UploadResponse {
                    success: true,
                    message: "File uploaded successfully".to_string(),
                    file_id: Some(file_id),
                }),
            )
        }
        Err(e) => {
            eprintln!("DB error: {}", e);
            let _ = fs::remove_file(&file_path).await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UploadResponse {
                    success: false,
                    message: format!("Database error: {}", e),
                    file_id: None,
                }),
            )
        }
    }
}

pub async fn list_pending_files(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Get list of users blocked by current user
    let blocked_by_me = sqlx::query_scalar!(
        "SELECT array_agg(blocked_user_id) FROM blocked_users WHERE user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(None)
    .unwrap_or(vec![]);
    
    // Get list of users who blocked current user
    let blocked_me = sqlx::query_scalar!(
        "SELECT array_agg(user_id) FROM blocked_users WHERE blocked_user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(None)
    .unwrap_or(vec![]);
    
    let files = sqlx::query!(
        "SELECT f.id, u.username as sender_username, f.encrypted_filename, f.file_size
         FROM files f
         JOIN users u ON f.sender_id = u.id
         WHERE f.recipient_id = $1 AND f.status = 'pending'
         AND f.expires_at > NOW()
         AND NOT (u.id = ANY($2) OR u.id = ANY($3))
         ORDER BY f.created_at DESC",
        user_id,
        &blocked_by_me as &[Uuid],
        &blocked_me as &[Uuid]
    )
    .fetch_all(&pool)
    .await;
    
    match files {
        Ok(rows) => {
            let list: Vec<serde_json::Value> = rows.into_iter()
                .map(|row| {
                    serde_json::json!({
                        "file_id": row.id,
                        "sender_username": row.sender_username,
                        "encrypted_filename": row.encrypted_filename,
                        "file_size": row.file_size
                    })
                })
                .collect();
            
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "files": list
            })))
        }
        Err(e) => {
            eprintln!("List pending error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "files": []
            })))
        }
    }
}

pub async fn list_sent_files(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    let blocked_by_me = sqlx::query_scalar!(
        "SELECT array_agg(blocked_user_id) FROM blocked_users WHERE user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(None)
    .unwrap_or(vec![]);
    
    let blocked_me = sqlx::query_scalar!(
        "SELECT array_agg(user_id) FROM blocked_users WHERE blocked_user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(None)
    .unwrap_or(vec![]);
    
    let files = sqlx::query!(
        "SELECT f.id, u.username as recipient_username, f.encrypted_filename, f.file_size, f.status
         FROM files f
         JOIN users u ON f.recipient_id = u.id
         WHERE f.sender_id = $1
         AND NOT (u.id = ANY($2) OR u.id = ANY($3))
         ORDER BY f.created_at DESC",
        user_id,
        &blocked_by_me as &[Uuid],
        &blocked_me as &[Uuid]
    )
    .fetch_all(&pool)
    .await;
    
    match files {
        Ok(rows) => {
            let list: Vec<serde_json::Value> = rows.into_iter()
                .map(|row| {
                    serde_json::json!({
                        "file_id": row.id,
                        "recipient_username": row.recipient_username,
                        "encrypted_filename": row.encrypted_filename,
                        "file_size": row.file_size,
                        "status": row.status
                    })
                })
                .collect();
            
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "files": list
            })))
        }
        Err(e) => {
            eprintln!("List sent error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "files": []
            })))
        }
    }
}

pub async fn list_received_files(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    let blocked_by_me = sqlx::query_scalar!(
        "SELECT array_agg(blocked_user_id) FROM blocked_users WHERE user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(None)
    .unwrap_or(vec![]);
    
    let blocked_me = sqlx::query_scalar!(
        "SELECT array_agg(user_id) FROM blocked_users WHERE blocked_user_id = $1",
        user_id
    )
    .fetch_one(&pool)
    .await
    .unwrap_or(None)
    .unwrap_or(vec![]);
    
    let files = sqlx::query!(
        "SELECT f.id, u.username as sender_username, f.encrypted_filename, f.file_size, f.status
         FROM files f
         JOIN users u ON f.sender_id = u.id
         WHERE f.recipient_id = $1
         AND NOT (u.id = ANY($2) OR u.id = ANY($3))
         ORDER BY f.created_at DESC",
        user_id,
        &blocked_by_me as &[Uuid],
        &blocked_me as &[Uuid]
    )
    .fetch_all(&pool)
    .await;
    
    match files {
        Ok(rows) => {
            let list: Vec<serde_json::Value> = rows.into_iter()
                .map(|row| {
                    serde_json::json!({
                        "file_id": row.id,
                        "sender_username": row.sender_username,
                        "encrypted_filename": row.encrypted_filename,
                        "file_size": row.file_size,
                        "status": row.status
                    })
                })
                .collect();
            
            (StatusCode::OK, Json(serde_json::json!({
                "success": true,
                "files": list
            })))
        }
        Err(e) => {
            eprintln!("List received error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "success": false,
                "files": []
            })))
        }
    }
}

pub async fn accept_file(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
    Path(file_id): Path<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    let result = sqlx::query!(
        "UPDATE files SET status = 'accepted' WHERE id = $1 AND recipient_id = $2 AND status = 'pending'",
        file_id, user_id
    )
    .execute(&pool)
    .await;
    
    match result {
        Ok(row) if row.rows_affected() > 0 => (
            StatusCode::OK,
            Json(serde_json::json!({ "success": true, "message": "File accepted" })),
        ),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "success": false, "message": "File not found" })),
        ),
        Err(e) => {
            eprintln!("Accept error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "message": "Failed to accept file" })),
            )
        }
    }
}

pub async fn decline_file(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
    Path(file_id): Path<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    let file = sqlx::query!(
        "SELECT encrypted_file_path FROM files WHERE id = $1 AND recipient_id = $2 AND status = 'pending'",
        file_id, user_id
    )
    .fetch_optional(&pool)
    .await;
    
    let file = match file {
        Ok(Some(f)) => f,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "success": false, "message": "File not found" })),
            );
        }
    };
    
    let _ = sqlx::query!(
        "UPDATE files SET status = 'declined' WHERE id = $1",
        file_id
    )
    .execute(&pool)
    .await;
    
    let _ = fs::remove_file(PathBuf::from(&file.encrypted_file_path)).await;
    
    (
        StatusCode::OK,
        Json(serde_json::json!({ "success": true, "message": "File declined" })),
    )
}

pub async fn cancel_file(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
    Path(file_id): Path<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    let file = sqlx::query!(
        "SELECT encrypted_file_path FROM files WHERE id = $1 AND sender_id = $2 AND status = 'pending'",
        file_id, user_id
    )
    .fetch_optional(&pool)
    .await;
    
    let file = match file {
        Ok(Some(f)) => f,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "success": false, "message": "File not found" })),
            );
        }
    };
    
    let _ = sqlx::query!(
        "UPDATE files SET status = 'cancelled' WHERE id = $1",
        file_id
    )
    .execute(&pool)
    .await;
    
    let _ = fs::remove_file(PathBuf::from(&file.encrypted_file_path)).await;
    
    (
        StatusCode::OK,
        Json(serde_json::json!({ "success": true, "message": "File cancelled" })),
    )
}

pub async fn download_file(
    Extension(pool): Extension<PgPool>,
    Extension(user_id): Extension<Uuid>,
    Path(file_id): Path<Uuid>,
) -> (StatusCode, Json<serde_json::Value>) {
    let file = sqlx::query!(
        "SELECT encrypted_file_path, encrypted_session_key, encrypted_filename
         FROM files
         WHERE id = $1 AND recipient_id = $2 AND status = 'accepted'",
        file_id, user_id
    )
    .fetch_optional(&pool)
    .await;
    
    let file = match file {
        Ok(Some(f)) => f,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "success": false, "message": "File not found or not accepted" })),
            );
        }
    };
    
    let file_data = match fs::read(&file.encrypted_file_path).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Read error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "success": false, "message": "Cannot read file" })),
            );
        }
    };
    
    use base64::Engine;
    let encoded_data = base64::engine::general_purpose::STANDARD.encode(&file_data);
    
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "encrypted_data": encoded_data,
            "encrypted_session_key": file.encrypted_session_key,
            "encrypted_filename": file.encrypted_filename
        })),
    )
}
