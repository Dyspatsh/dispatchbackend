use axum::{extract::Extension, http::StatusCode, response::Json, Json as AxumJson};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use bcrypt::{hash, DEFAULT_COST};
use rand::{distributions::Alphanumeric, Rng};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub pin: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub message: String,
    pub recovery_phrase: Option<String>,
    pub user_id: Option<Uuid>,
}

// Validate username: 3-16 chars, letters and numbers only
fn is_valid_username(username: &str) -> bool {
    if username.len() < 3 || username.len() > 16 {
        return false;
    }
    username.chars().all(|c| c.is_ascii_alphanumeric())
}

// Validate password: 12-16 chars, must contain letter, number, and symbol
fn is_valid_password(password: &str) -> bool {
    if password.len() < 12 || password.len() > 16 {
        return false;
    }
    let has_letter = password.chars().any(|c| c.is_ascii_alphabetic());
    let has_number = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric());
    has_letter && has_number && has_symbol
}

// Validate PIN: exactly 6 digits
fn is_valid_pin(pin: &str) -> bool {
    pin.len() == 6 && pin.chars().all(|c| c.is_ascii_digit())
}

// Sanitize input to prevent script injection
fn sanitize_input(input: &str) -> String {
    input.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")
}

pub async fn register(
    Extension(pool): Extension<PgPool>,
    AxumJson(payload): AxumJson<RegisterRequest>,
) -> (StatusCode, Json<RegisterResponse>) {
    // Sanitize inputs
    let username = sanitize_input(&payload.username);
    
    // Validate username
    if !is_valid_username(&username) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterResponse {
                success: false,
                message: "Username must be 3-16 characters, letters and numbers only".to_string(),
                recovery_phrase: None,
                user_id: None,
            }),
        );
    }
    
    // Validate password
    if !is_valid_password(&payload.password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterResponse {
                success: false,
                message: "Password must be 12-16 characters with letters, numbers, and symbols".to_string(),
                recovery_phrase: None,
                user_id: None,
            }),
        );
    }
    
    // Validate PIN
    if !is_valid_pin(&payload.pin) {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterResponse {
                success: false,
                message: "PIN must be exactly 6 digits".to_string(),
                recovery_phrase: None,
                user_id: None,
            }),
        );
    }
    
    // Check if username exists
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)"
    )
    .bind(&username)
    .fetch_one(&pool)
    .await
    .unwrap_or(false);
    
    if exists {
        return (
            StatusCode::CONFLICT,
            Json(RegisterResponse {
                success: false,
                message: "Username already taken".to_string(),
                recovery_phrase: None,
                user_id: None,
            }),
        );
    }
    
    // Generate 64-character recovery phrase
    let recovery_phrase: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    
    // Hash password and PIN
    let password_hash = match hash(&payload.password, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Password hash error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RegisterResponse {
                    success: false,
                    message: "Registration failed".to_string(),
                    recovery_phrase: None,
                    user_id: None,
                }),
            );
        }
    };
    
    let pin_hash = match hash(&payload.pin, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("PIN hash error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RegisterResponse {
                    success: false,
                    message: "Registration failed".to_string(),
                    recovery_phrase: None,
                    user_id: None,
                }),
            );
        }
    };
    
    let recovery_hash = match hash(&recovery_phrase, DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Recovery hash error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RegisterResponse {
                    success: false,
                    message: "Registration failed".to_string(),
                    recovery_phrase: None,
                    user_id: None,
                }),
            );
        }
    };
    
    let user_id = Uuid::new_v4();
    
    let result = sqlx::query(
        "INSERT INTO users (id, username, password_hash, pin_hash, recovery_phrase_hash) 
         VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(user_id)
    .bind(&username)
    .bind(password_hash)
    .bind(pin_hash)
    .bind(recovery_hash)
    .execute(&pool)
    .await;
    
    match result {
        Ok(_) => (
            StatusCode::CREATED,
            Json(RegisterResponse {
                success: true,
                message: "User registered. Save this recovery phrase!".to_string(),
                recovery_phrase: Some(recovery_phrase),
                user_id: Some(user_id),
            }),
        ),
        Err(e) => {
            eprintln!("Registration error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RegisterResponse {
                    success: false,
                    message: "Failed to register".to_string(),
                    recovery_phrase: None,
                    user_id: None,
                }),
            )
        }
    }
}
