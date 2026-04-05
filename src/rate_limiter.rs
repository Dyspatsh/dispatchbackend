//! Simple IP-based rate limiter for auth endpoints
//! Uses in-memory HashMap with automatic cleanup

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration};
use axum::{
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    middleware::Next,
    extract::Extension,
};
use axum::body::Body;

/// Rate limiter configuration
#[derive(Clone)]
pub struct RateLimiterConfig {
    pub max_requests: u32,
    pub window_seconds: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            max_requests: 5,
            window_seconds: 60,
        }
    }
}

/// Rate limiter state stored in memory
#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    config: RateLimiterConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    /// Check if a request from an IP is allowed
    pub fn is_allowed(&self, ip: &str) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_seconds);
        
        let mut requests = self.requests.lock().unwrap();
        let ip_requests = requests.entry(ip.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests outside the window
        ip_requests.retain(|&timestamp| now.duration_since(timestamp) < window);
        
        // Check if under limit
        if ip_requests.len() < self.config.max_requests as usize {
            ip_requests.push(now);
            true
        } else {
            false
        }
    }

    /// Clean up old entries (call periodically)
    pub fn cleanup(&self) {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_seconds);
        
        let mut requests = self.requests.lock().unwrap();
        requests.retain(|_, timestamps| {
            timestamps.retain(|&t| now.duration_since(t) < window);
            !timestamps.is_empty()
        });
    }
}

/// Get client IP from request
fn get_client_ip<B>(req: &Request<B>) -> String {
    // Try X-Forwarded-For header first (for proxies)
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(ip) = forwarded_str.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }
    
    // Try X-Real-IP header
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip) = real_ip.to_str() {
            return ip.to_string();
        }
    }
    
    // Fallback to socket address
    if let Some(addr) = req.extensions().get::<std::net::SocketAddr>() {
        return addr.ip().to_string();
    }
    
    "unknown".to_string()
}

/// Rate limiting middleware for login and recovery (5 requests per minute)
pub async fn auth_rate_limit_middleware(
    Extension(limiter): Extension<RateLimiter>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = get_client_ip(&req);
    
    if limiter.is_allowed(&ip) {
        next.run(req).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "success": false,
                "message": "Rate limit exceeded. Too many attempts. Please try again later."
            })),
        ).into_response()
    }
}

/// Stricter rate limiting middleware for registration (3 requests per 5 minutes)
pub async fn register_rate_limit_middleware(
    Extension(limiter): Extension<RateLimiter>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let ip = get_client_ip(&req);
    
    if limiter.is_allowed(&ip) {
        next.run(req).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            axum::Json(serde_json::json!({
                "success": false,
                "message": "Rate limit exceeded. Too many registration attempts. Please try again later."
            })),
        ).into_response()
    }
}

/// Spawn cleanup task to prevent memory leaks
pub fn start_cleanup_task(limiter: RateLimiter) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // Clean every 5 minutes
        loop {
            interval.tick().await;
            limiter.cleanup();
        }
    });
}
