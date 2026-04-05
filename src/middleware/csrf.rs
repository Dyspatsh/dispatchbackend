use axum::{
    http::{Request, HeaderValue},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;

// Simple in-memory token store (use Redis in production)
static CSRF_TOKENS: Lazy<Mutex<HashMap<String, u64>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn generate_csrf_token(user_id: Uuid) -> String {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let input = format!("{}{}", user_id, timestamp);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let token = hex::encode(hasher.finalize());
    
    // Store token with expiration (1 hour)
    CSRF_TOKENS.lock().unwrap().insert(token.clone(), timestamp + 3600);
    
    token
}

pub async fn csrf_middleware<B>(
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, Response> {
    // Skip CSRF check for GET, HEAD, OPTIONS requests
    if req.method() == axum::http::Method::GET 
        || req.method() == axum::http::Method::HEAD
        || req.method() == axum::http::Method::OPTIONS {
        return Ok(next.run(req).await);
    }
    
    // Get CSRF token from header
    let csrf_token = req.headers()
        .get("X-CSRF-Token")
        .and_then(|h| h.to_str().ok())
        .map(String::from);
    
    let stored_tokens = CSRF_TOKENS.lock().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    match csrf_token {
        Some(token) if stored_tokens.contains_key(&token) && stored_tokens[&token] > now => {
            Ok(next.run(req).await)
        }
        _ => {
            let mut response = Response::new(axum::body::Body::from("Invalid CSRF token"));
            *response.status_mut() = axum::http::StatusCode::FORBIDDEN;
            Err(response)
        }
    }
}
