use axum::{extract::Extension, http::StatusCode, response::Json, Json as AxumJson};
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};
//use uuid::Uuid;

use crate::app_state::AppState;

#[derive(Deserialize)]
pub struct RecoveryRequest {
    pub username: String,
    pub recovery_phrase: String,
    pub new_password: Option<String>,
    pub new_password_confirm: Option<String>,
    pub new_pin: Option<String>,
    pub new_pin_confirm: Option<String>,
}

#[derive(Serialize)]
pub struct RecoveryResponse {
    pub success: bool,
    pub message: String,
}

// Validate password: 12-16 chars, must contain letter, number, and symbol (no spaces)
fn is_valid_password(password: &str) -> bool {
    if password.len() < 12 || password.len() > 16 {
        return false;
    }
    let has_letter = password.chars().any(|c| c.is_ascii_alphabetic());
    let has_number = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_ascii_alphanumeric() && c != ' ');
    has_letter && has_number && has_symbol
}

// Validate PIN: exactly 6 digits
fn is_valid_pin(pin: &str) -> bool {
    pin.len() == 6 && pin.chars().all(|c| c.is_ascii_digit())
}

pub async fn recover_account(
    Extension(state): Extension<AppState>,
    AxumJson(payload): AxumJson<RecoveryRequest>,
) -> (StatusCode, Json<RecoveryResponse>) {
    let user = sqlx::query!(
        "SELECT id, recovery_phrase_hash FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&state.pool)
    .await;
    
    let user = match user {
        Ok(Some(u)) => u,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(RecoveryResponse {
                    success: false,
                    message: "Invalid recovery phrase".to_string(),
                }),
            );
        }
    };
    
    let phrase_valid = match user.recovery_phrase_hash {
        Some(hash) => match verify(&payload.recovery_phrase, &hash) {
            Ok(true) => true,
            _ => false,
        },
        None => false,
    };
    
    if !phrase_valid {
        return (
            StatusCode::NOT_FOUND,
            Json(RecoveryResponse {
                success: false,
                message: "Invalid recovery phrase".to_string(),
            }),
        );
    }
    
    // Validate password if provided
    if let Some(ref new_password) = payload.new_password {
        if !is_valid_password(new_password) {
            return (
                StatusCode::BAD_REQUEST,
                Json(RecoveryResponse {
                    success: false,
                    message: "Password must be 12-16 characters with letters, numbers, and symbols (no spaces)".to_string(),
                }),
            );
        }
        
        // Check confirmation
        if let Some(ref confirm) = payload.new_password_confirm {
            if new_password != confirm {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(RecoveryResponse {
                        success: false,
                        message: "Password confirmation does not match".to_string(),
                    }),
                );
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(RecoveryResponse {
                    success: false,
                    message: "Password confirmation is required".to_string(),
                }),
            );
        }
    }
    
    // Validate PIN if provided
    if let Some(ref new_pin) = payload.new_pin {
        if !is_valid_pin(new_pin) {
            return (
                StatusCode::BAD_REQUEST,
                Json(RecoveryResponse {
                    success: false,
                    message: "PIN must be exactly 6 digits".to_string(),
                }),
            );
        }
        
        // Check confirmation
        if let Some(ref confirm) = payload.new_pin_confirm {
            if new_pin != confirm {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(RecoveryResponse {
                        success: false,
                        message: "PIN confirmation does not match".to_string(),
                    }),
                );
            }
        } else {
            return (
                StatusCode::BAD_REQUEST,
                Json(RecoveryResponse {
                    success: false,
                    message: "PIN confirmation is required".to_string(),
                }),
            );
        }
    }
    
    let has_updates = payload.new_password.is_some() || payload.new_pin.is_some();
    
    if !has_updates {
        return (
            StatusCode::BAD_REQUEST,
            Json(RecoveryResponse {
                success: false,
                message: "No changes provided".to_string(),
            }),
        );
    }
    
    let mut tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Transaction error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RecoveryResponse {
                    success: false,
                    message: "Recovery failed".to_string(),
                }),
            );
        }
    };
    
    let mut update_success = true;
    
    if let Some(new_password) = &payload.new_password {
        if let Ok(password_hash) = hash(new_password, DEFAULT_COST) {
            let result = sqlx::query!(
                "UPDATE users SET password_hash = $1 WHERE id = $2",
                password_hash,
                user.id
            )
            .execute(&mut *tx)
            .await;
            
            if result.is_err() {
                update_success = false;
            }
        } else {
            update_success = false;
        }
    }
    
    if let Some(new_pin) = &payload.new_pin {
        if let Ok(pin_hash) = hash(new_pin, DEFAULT_COST) {
            let result = sqlx::query!(
                "UPDATE users SET pin_hash = $1 WHERE id = $2",
                pin_hash,
                user.id
            )
            .execute(&mut *tx)
            .await;
            
            if result.is_err() {
                update_success = false;
            }
        } else {
            update_success = false;
        }
    }
    
    if update_success {
        match tx.commit().await {
            Ok(_) => {
                // Invalidate all existing sessions by not doing anything special
                // (JWTs will expire naturally)
                (
                    StatusCode::OK,
                    Json(RecoveryResponse {
                        success: true,
                        message: "Account recovered successfully. Please login with your new credentials.".to_string(),
                    }),
                )
            },
            Err(e) => {
                eprintln!("Commit error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(RecoveryResponse {
                        success: false,
                        message: "Recovery failed".to_string(),
                    }),
                )
            }
        }
    } else {
        let _ = tx.rollback().await;
        (
            StatusCode::BAD_REQUEST,
            Json(RecoveryResponse {
                success: false,
                message: "Failed to update credentials. Please try again.".to_string(),
            }),
        )
    }
}
