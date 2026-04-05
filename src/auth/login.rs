use axum::{extract::Extension, http::StatusCode, response::Json, Json as AxumJson};
use serde::{Deserialize, Serialize};
use bcrypt::verify;  // Add this import
use jsonwebtoken::{encode, Header};
use chrono::{Utc, Duration};
use uuid::Uuid;

use crate::app_state::AppState;
use crate::Claims;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub pin: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    pub token: Option<String>,
    pub user_id: Option<Uuid>,
    pub role: Option<String>,
}

// Dummy hash for timing attack protection (bcrypt of "dummy")
const DUMMY_HASH: &str = "$2b$12$dummyhashfordummyhashfordummyhashfordumm";

pub async fn login(
    Extension(state): Extension<AppState>,
    AxumJson(payload): AxumJson<LoginRequest>,
) -> (StatusCode, Json<LoginResponse>) {
    // Sanitize username
    let username = sanitize_input(&payload.username);
    
    // Query user
    let user = sqlx::query!(
        "SELECT id, password_hash, pin_hash, role, is_banned FROM users WHERE username = $1",
        username
    )
    .fetch_optional(&state.pool)
    .await;
    
    let (user_exists, stored_password_hash, stored_pin_hash, user_id, user_role, is_banned) = match user {
        Ok(Some(u)) => (true, u.password_hash, u.pin_hash, u.id, u.role, u.is_banned.unwrap_or(false)),
        Ok(None) => (false, None, None, Uuid::nil(), None, false),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LoginResponse {
                    success: false,
                    message: "Login failed".to_string(),
                    token: None,
                    user_id: None,
                    role: None,
                }),
            );
        }
    };
    
    // Check if user is banned (only if exists)
    if user_exists && is_banned {
        return (
            StatusCode::FORBIDDEN,
            Json(LoginResponse {
                success: false,
                message: "Account is banned".to_string(),
                token: None,
                user_id: None,
                role: None,
            }),
        );
    }
    
    // Timing attack protection: always verify both password and PIN with dummy hashes if needed
    let password_hash_to_verify = if user_exists {
        stored_password_hash.as_deref().unwrap_or(DUMMY_HASH)
    } else {
        DUMMY_HASH
    };
    
    let pin_hash_to_verify = if user_exists {
        stored_pin_hash.as_deref().unwrap_or(DUMMY_HASH)
    } else {
        DUMMY_HASH
    };
    
    // Verify both password and PIN (timing-safe)
    let password_valid = match verify(&payload.password, password_hash_to_verify) {
        Ok(v) => v,
        Err(_) => false,
    };
    
    let pin_valid = match verify(&payload.pin, pin_hash_to_verify) {
        Ok(v) => v,
        Err(_) => false,
    };
    
    // If user doesn't exist or credentials are invalid, return generic error
    if !user_exists || !password_valid || !pin_valid {
        // Add small random delay to prevent timing attacks
        tokio::time::sleep(tokio::time::Duration::from_millis(rand::random::<u64>() % 100)).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(LoginResponse {
                success: false,
                message: "Invalid credentials".to_string(),
                token: None,
                user_id: None,
                role: None,
            }),
        );
    }
    
    // Generate JWT
    let expiration = (Utc::now() + Duration::days(7)).timestamp() as usize;
    let user_role_str = user_role.unwrap_or_else(|| "free".to_string());
    
    let claims = Claims {
        sub: user_id.to_string(),
        exp: expiration,
        role: user_role_str.clone(),
    };
    
    let token = match encode(&Header::default(), &claims, &state.jwt_encoding_key) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Token error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LoginResponse {
                    success: false,
                    message: "Login failed".to_string(),
                    token: None,
                    user_id: None,
                    role: None,
                }),
            );
        }
    };
    
    // Update last_seen (don't block on error)
    let _ = sqlx::query!(
        "UPDATE users SET last_seen = NOW() WHERE id = $1",
        user_id
    )
    .execute(&state.pool)
    .await;
    
    (
        StatusCode::OK,
        Json(LoginResponse {
            success: true,
            message: "Login successful".to_string(),
            token: Some(token),
            user_id: Some(user_id),
            role: Some(user_role_str),
        }),
    )
}

fn sanitize_input(input: &str) -> String {
    input.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")
}
