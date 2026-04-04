use axum::{
    Router, routing::{get, post}, response::Json, extract::Extension,
    middleware, http::Method,  // Removed HeaderValue since it's unused
};
use tower_http::cors::{CorsLayer, Any};
use serde_json::json;
use tokio::net::TcpListener;
use dotenv::dotenv;
use std::env;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

mod auth;
mod handlers;

use auth::register::register;
use auth::login::login;
use auth::recovery::recover_account;
use auth::public_key::upload_public_key;  // ADD THIS IMPORT
use handlers::*;

// FIXED: Proper JWT claims with expiration validation
#[derive(serde::Serialize, serde::Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    role: String,
}

async fn auth_middleware(
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<axum::response::Response, axum::response::Response> {
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());
    
    let user_id = if let Some(header) = auth_header {
        if header.starts_with("Bearer ") {
            let token = &header[7..];
            use jsonwebtoken::{decode, DecodingKey, Validation};
            
            let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
            
            // FIXED: Proper validation with expiration check
            let mut validation = Validation::default();
            validation.validate_exp = true;
            validation.leeway = 0;
            
            let decoded = decode::<Claims>(
                token,
                &DecodingKey::from_secret(jwt_secret.as_bytes()),
                &validation,
            );
            
            match decoded {
                Ok(data) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as usize;
                    
                    if data.claims.exp < now {
                        None
                    } else {
                        Some(Uuid::parse_str(&data.claims.sub).ok())
                    }
                },
                Err(_) => None,
            }.flatten()
        } else { None }
    } else { None };
    
    if let Some(uid) = user_id {
        req.extensions_mut().insert(uid);
        Ok(next.run(req).await)
    } else {
        let mut response = axum::response::Response::new(axum::body::Body::from("Unauthorized"));
        *response.status_mut() = axum::http::StatusCode::UNAUTHORIZED;
        Ok(response)
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();
    
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");
    
    let port = env::var("SERVER_PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    
    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(Any);
    
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/", get(health_check))
        .route("/health", get(health_check))
        .route("/version", get(version_check))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/recover", post(recover_account))
        .route("/users/status/:username", get(check_user_status))
        .route("/users/public-key/:username", get(get_public_key_by_username))
        .route("/users/search", get(search_users));
    
    // Protected routes (auth required)
    let protected_routes = Router::new()
        .route("/users/block/:username", post(block_user))
        .route("/users/unblock/:username", post(unblock_user))
        .route("/users/blocked", get(get_blocked_users))
        .route("/users/is-blocked-by/:username", get(is_blocked_by))
        .route("/users/public-key/upload", post(upload_public_key))
        .route("/files/upload", post(upload_file))
        .route("/files/pending", get(list_pending_files))
        .route("/files/sent", get(list_sent_files))
        .route("/files/received", get(list_received_files))
        .route("/files/accept/:file_id", post(accept_file))
        .route("/files/decline/:file_id", post(decline_file))
        .route("/files/cancel/:file_id", post(cancel_file))
        .route("/files/download/:file_id", get(download_file))
        .layer(middleware::from_fn(auth_middleware));
    
    let app = public_routes
        .merge(protected_routes)
        .layer(cors)
        .layer(Extension(pool));
    
    println!("Dispatch server running on http://{}", addr);
    
    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "service": "dispatch-server" }))
}

async fn version_check() -> Json<serde_json::Value> {
    match std::fs::read_to_string("/opt/dispatch/version.json") {
        Ok(content) => {
            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(json) => Json(json),
                Err(_) => Json(json!({
                    "version": "1.0.0",
                    "download_url": "https://yourdomain.com/download/dispatch-setup.exe",
                    "release_notes": "Update available",
                    "required": true
                })),
            }
        }
        Err(_) => Json(json!({
            "version": "1.0.0",
            "download_url": "https://yourdomain.com/download/dispatch-setup.exe",
            "release_notes": "Update available",
            "required": true
        })),
    }
}
