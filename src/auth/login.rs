use axum::{extract::Extension, http::StatusCode, response::Json, Json as AxumJson};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use bcrypt::verify;
use jsonwebtoken::{encode, EncodingKey, Header};
use chrono::{Utc, Duration};
use uuid::Uuid;
use std::env;

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

#[derive(Serialize)]
struct Claims {
    sub: String,
    exp: usize,
    role: String,
}

fn sanitize_input(input: &str) -> String {
    input.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")
}

pub async fn login(
    Extension(pool): Extension<PgPool>,
    AxumJson(payload): AxumJson<LoginRequest>,
) -> (StatusCode, Json<LoginResponse>) {
    let username = sanitize_input(&payload.username);
    
    let user = sqlx::query!(
        "SELECT id, password_hash, pin_hash, role FROM users WHERE username = $1",
        username
    )
    .fetch_optional(&pool)
    .await;
    
    let user = match user {
        Ok(Some(u)) => u,
        _ => {
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
    };
    
    // Verify password
    let password_valid = match verify(&payload.password, &user.password_hash.unwrap_or_default()) {
        Ok(v) => v,
        Err(_) => false,
    };
    
    if !password_valid {
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
    
    // Verify PIN
    let pin_valid = match verify(&payload.pin, &user.pin_hash.unwrap_or_default()) {
        Ok(v) => v,
        Err(_) => false,
    };
    
    if !pin_valid {
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
    
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let expiration = (Utc::now() + Duration::days(7)).timestamp() as usize;
    
    let user_role = user.role.unwrap_or_else(|| "free".to_string());
    
    let claims = Claims {
        sub: user.id.to_string(),
        exp: expiration,
        role: user_role.clone(),
    };
    
    let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(jwt_secret.as_bytes())) {
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
    
    (
        StatusCode::OK,
        Json(LoginResponse {
            success: true,
            message: "Login successful".to_string(),
            token: Some(token),
            user_id: Some(user.id),
            role: Some(user_role),
        }),
    )
}
