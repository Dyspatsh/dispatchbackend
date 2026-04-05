//! Custom error handlers for rate limiting and other errors

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response, Json},
};
use serde_json::json;

/// Handler for rate limit exceeded errors
pub async fn handle_rate_limit_error(err: tower_governor::error::Error) -> Response {
    let (status, message) = match err {
        tower_governor::error::Error::RateLimitExceeded => (
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded. Please try again later.".to_string(),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error".to_string(),
        ),
    };

    (status, Json(json!({ "success": false, "message": message }))).into_response()
}
