use axum::{extract::Extension, http::StatusCode, response::Json, Json as AxumJson};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use bcrypt::{hash, verify, DEFAULT_COST};

#[derive(Deserialize)]
pub struct RecoveryRequest {
    pub username: String,
    pub recovery_phrase: String,
    pub new_password: Option<String>,
    pub new_pin: Option<String>,
}

#[derive(Serialize)]
pub struct RecoveryResponse {
    pub success: bool,
    pub message: String,
}

pub async fn recover_account(
    Extension(pool): Extension<PgPool>,
    AxumJson(payload): AxumJson<RecoveryRequest>,
) -> (StatusCode, Json<RecoveryResponse>) {
    let user = sqlx::query!(
        "SELECT id, recovery_phrase_hash FROM users WHERE username = $1",
        payload.username
    )
    .fetch_optional(&pool)
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
    
    let mut tx = match pool.begin().await {
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
        if new_password.len() >= 12 && new_password.len() <= 64 {
            let has_letter = new_password.chars().any(|c| c.is_ascii_alphabetic());
            let has_number = new_password.chars().any(|c| c.is_ascii_digit());
            let has_symbol = new_password.chars().any(|c| !c.is_ascii_alphanumeric());
            
            if has_letter && has_number && has_symbol {
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
            } else {
                update_success = false;
            }
        } else {
            update_success = false;
        }
    }
    
    if let Some(new_pin) = &payload.new_pin {
        if new_pin.len() == 6 && new_pin.chars().all(|c| c.is_ascii_digit()) {
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
        } else {
            update_success = false;
        }
    }
    
    if update_success {
        match tx.commit().await {
            Ok(_) => (
                StatusCode::OK,
                Json(RecoveryResponse {
                    success: true,
                    message: "Account recovered successfully".to_string(),
                }),
            ),
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
                message: "Invalid new password or PIN format. Password: 12-64 chars with letter, number, symbol. PIN: 6 digits.".to_string(),
            }),
        )
    }
}
