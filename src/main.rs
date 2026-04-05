use axum::{
    Router, routing::{get, post}, response::Json, extract::Extension,
    middleware, http::Method,
};
use tower_http::cors::{CorsLayer, Any};
use tower_http::limit::RequestBodyLimitLayer;
use serde_json::json;
use tokio::net::TcpListener;
use dotenv::dotenv;
use std::env;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

mod app_state;
mod auth;
mod handlers;
mod rate_limiter;

use app_state::AppState;
use auth::register::register;
use auth::login::login;
use auth::recovery::recover_account;
use auth::public_key::upload_public_key;
use handlers::*;
use rate_limiter::{rate_limit_middleware, start_rate_limiter_cleanup};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Claims {
    sub: String,
    exp: usize,
    role: String,
}

async fn auth_middleware(
    req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<axum::response::Response, axum::response::Response> {
    // Extract state from request extensions - NOT wrapped in Arc
    let state = req.extensions()
        .get::<AppState>()
        .cloned()
        .ok_or_else(|| {
            axum::response::Response::builder()
                .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from("Internal server error - State not found"))
                .unwrap()
        })?;
    
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    let user_id_result = if let Some(header) = auth_header {
        if header.starts_with("Bearer ") {
            let token = &header[7..];
            use jsonwebtoken::{decode, Validation};

            let mut validation = Validation::default();
            validation.validate_exp = true;
            validation.leeway = 0;

            let decoded = decode::<Claims>(
                token,
                &state.jwt_decoding_key,
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

    let user_id = match user_id_result {
        Some(uid) => uid,
        None => {
            return Err(axum::response::Response::builder()
                .status(axum::http::StatusCode::UNAUTHORIZED)
                .body(axum::body::Body::from("Unauthorized"))
                .unwrap());
        }
    };

    // Verify user still exists and is not banned
    let user_check = sqlx::query!(
        "SELECT is_banned FROM users WHERE id = $1",
        user_id
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| {
        axum::response::Response::builder()
            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
            .body(axum::body::Body::from("Database error"))
            .unwrap()
    })?;
    
    match user_check {
        Some(user) if !user.is_banned.unwrap_or(false) => {
            let mut req = req;
            req.extensions_mut().insert(user_id);
            Ok(next.run(req).await)
        }
        Some(_) => {
            Err(axum::response::Response::builder()
                .status(axum::http::StatusCode::FORBIDDEN)
                .body(axum::body::Body::from("Account is banned"))
                .unwrap())
        }
        None => {
            Err(axum::response::Response::builder()
                .status(axum::http::StatusCode::UNAUTHORIZED)
                .body(axum::body::Body::from("User not found"))
                .unwrap())
        }
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

    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let state = AppState::new(pool, jwt_secret).await;  // Don't wrap in Arc

    let port = env::var("SERVER_PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);

    // Read allowed origins from environment variable
    let allowed_origins: Vec<axum::http::HeaderValue> = env::var("ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "https://localhost".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();

    println!("CORS allowed origins: {:?}", allowed_origins);
    println!("Starting server on http://{}", addr);

    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(Any);

    let request_limit = RequestBodyLimitLayer::new(100 * 1024 * 1024); // 100MB limit

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
        .route("/users/storage", get(get_storage_info))
        .route("/files/upload", post(upload_file).layer(request_limit))
        .route("/files/pending", get(list_pending_files))
        .route("/files/sent", get(list_sent_files))
        .route("/files/received", get(list_received_files))
        .route("/files/accept/:file_id", post(accept_file))
        .route("/files/decline/:file_id", post(decline_file))
        .route("/files/cancel/:file_id", post(cancel_file))
        .route("/files/download/:file_id", get(download_file))
        .layer(middleware::from_fn(auth_middleware));

    // Apply rate limiting to all routes
    let app = public_routes
        .merge(protected_routes)
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(cors)
        .layer(Extension(state));  // Add state as extension (not Arc)

    // Start rate limiter cleanup task
    start_rate_limiter_cleanup();

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
