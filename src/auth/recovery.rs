use axum::{extract::Extension, http::StatusCode, response::Json, Json as AxumJson};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use bcrypt::{hash, verify, DEFAULT_COST};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct RecoveryRequest {
    pub recovery_phrase: String,
    pub new_username: Option<String>,
    pub new_password: Option<String>,
    pub new_pin: Option<String>,
}

#[derive(Serialize)]
pub struct RecoveryResponse {
    pub success: bool,
    pub message: String,
}

fn sanitize_input(input: &str) -> String {
    input.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")
}

pub async fn recover_account(
    Extension(pool): Extension<PgPool>,
    AxumJson(payload): AxumJson<RecoveryRequest>,
) -> (StatusCode, Json<RecoveryResponse>) {
    // First, find the user by recovery phrase
    let users = sqlx::query!(
        "SELECT id, recovery_phrase_hash FROM users WHERE recovery_phrase_hash IS NOT NULL"
    )
    .fetch_all(&pool)
    .await;
    
    let users = match users {
        Ok(u) => u,
        Err(e) => {
            eprintln!("Recovery error - DB query: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RecoveryResponse {
                    success: false,
                    message: "Recovery failed. Please try again.".to_string(),
                }),
            );
        }
    };
    
    // Find matching recovery phrase
    let mut user_id: Option<Uuid> = None;
    for user in users {
        // Get the hash value, skip if None
        let hash_value = match user.recovery_phrase_hash {
            Some(h) => h,
            None => continue,
        };
        
        match verify(&payload.recovery_phrase, &hash_value) {
            Ok(true) => {
                user_id = Some(user.id);
                break;
            }
            Ok(false) => continue,
            Err(e) => {
                eprintln!("Recovery error - verify: {}", e);
                continue;
            }
        }
    }
    
    // If no user found with this recovery phrase, return error
    let user_id = match user_id {
        Some(id) => id,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(RecoveryResponse {
                    success: false,
                    message: "Invalid recovery phrase. No account found with this phrase.".to_string(),
                }),
            );
        }
    };
    
    // At least one field must be provided to update
    let has_updates = payload.new_username.is_some() || 
                      payload.new_password.is_some() || 
                      payload.new_pin.is_some();
    
    if !has_updates {
        return (
            StatusCode::BAD_REQUEST,
            Json(RecoveryResponse {
                success: false,
                message: "No changes provided. Please specify what to update.".to_string(),
            }),
        );
    }
    
    // Update username if provided
    if let Some(new_username) = &payload.new_username {
        let sanitized = sanitize_input(new_username);
        if sanitized.len() >= 3 && sanitized.len() <= 16 && 
           sanitized.chars().all(|c| c.is_ascii_alphanumeric()) {
            let _ = sqlx::query!(
                "UPDATE users SET username = $1 WHERE id = $2",
                sanitized,
                user_id
            )
            .execute(&pool)
            .await;
        }
    }
    
    // Update password if provided
    if let Some(new_password) = &payload.new_password {
        if new_password.len() >= 12 && new_password.len() <= 16 {
            let has_letter = new_password.chars().any(|c| c.is_ascii_alphabetic());
            let has_number = new_password.chars().any(|c| c.is_ascii_digit());
            let has_symbol = new_password.chars().any(|c| !c.is_ascii_alphanumeric());
            
            if has_letter && has_number && has_symbol {
                if let Ok(password_hash) = hash(new_password, DEFAULT_COST) {
                    let _ = sqlx::query!(
                        "UPDATE users SET password_hash = $1 WHERE id = $2",
                        password_hash,
                        user_id
                    )
                    .execute(&pool)
                    .await;
                }
            }
        }
    }
    
    // Update PIN if provided
    if let Some(new_pin) = &payload.new_pin {
        if new_pin.len() == 6 && new_pin.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(pin_hash) = hash(new_pin, DEFAULT_COST) {
                let _ = sqlx::query!(
                    "UPDATE users SET pin_hash = $1 WHERE id = $2",
                    pin_hash,
                    user_id
                )
                .execute(&pool)
                .await;
            }
        }
    }
    
    (
        StatusCode::OK,
        Json(RecoveryResponse {
            success: true,
            message: "Account recovered successfully. You can now log in with your new credentials.".to_string(),
        }),
    )
}
