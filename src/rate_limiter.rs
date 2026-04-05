use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, Duration};
use once_cell::sync::Lazy;
use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    body::Body,
};

// Rate limiter state with better tracking
#[derive(Debug, Clone)]
struct RateLimitEntry {
    timestamps: Vec<Instant>,
    count: usize,
}

static RATE_LIMITER: Lazy<Mutex<HashMap<String, RateLimitEntry>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub struct RateLimiter;

impl RateLimiter {
    pub fn check_limit(key: &str, max_requests: usize, window_secs: u64) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(window_secs);
        
        let mut map = RATE_LIMITER.lock().unwrap();
        let entry = map.entry(key.to_string()).or_insert(RateLimitEntry {
            timestamps: Vec::new(),
            count: 0,
        });
        
        // Remove old timestamps
        entry.timestamps.retain(|&timestamp| timestamp.elapsed() < window);
        
        // Check if under limit
        if entry.timestamps.len() < max_requests {
            entry.timestamps.push(now);
            entry.count += 1;
            true
        } else {
            false
        }
    }
    
    pub fn cleanup_old_entries() {
        let mut map = RATE_LIMITER.lock().unwrap();
        map.retain(|_, entry| {
            entry.timestamps.retain(|&timestamp| timestamp.elapsed() < Duration::from_secs(3600));
            !entry.timestamps.is_empty()
        });
    }
    
    pub fn get_remaining(key: &str, max_requests: usize, window_secs: u64) -> usize {
        let window = Duration::from_secs(window_secs);
        let map = RATE_LIMITER.lock().unwrap();
        
        if let Some(entry) = map.get(key) {
            let valid_requests: Vec<_> = entry.timestamps.iter()
                .filter(|&&timestamp| timestamp.elapsed() < window)
                .collect();
            
            if valid_requests.len() >= max_requests {
                0
            } else {
                max_requests - valid_requests.len()
            }
        } else {
            max_requests
        }
    }
}

pub async fn rate_limit_middleware(
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get client IP or use a unique identifier
    let client_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .or_else(|| req.headers().get("x-real-ip").and_then(|h| h.to_str().ok()))
        .unwrap_or("unknown")
        .to_string();
    
    // Create a key based on IP and path
    let key = format!("{}:{}", client_ip, req.uri().path());
    
    // Different limits for different endpoints
    let (max_requests, window_secs) = if req.uri().path().starts_with("/auth/") {
        (5, 60) // 5 requests per minute for auth
    } else {
        (30, 60) // 30 requests per minute for other endpoints
    };
    
    if RateLimiter::check_limit(&key, max_requests, window_secs) {
        let remaining = RateLimiter::get_remaining(&key, max_requests, window_secs);
        let mut response = next.run(req).await;
        
        // Add rate limit headers
        response.headers_mut().insert(
            "X-RateLimit-Limit",
            axum::http::HeaderValue::from_str(&max_requests.to_string()).unwrap()
        );
        response.headers_mut().insert(
            "X-RateLimit-Remaining",
            axum::http::HeaderValue::from_str(&remaining.to_string()).unwrap()
        );
        response.headers_mut().insert(
            "X-RateLimit-Reset",
            axum::http::HeaderValue::from_str(&window_secs.to_string()).unwrap()
        );
        
        Ok(response)
    } else {
        Err(StatusCode::TOO_MANY_REQUESTS)
    }
}

// Cleanup task for rate limiter
pub fn start_rate_limiter_cleanup() {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            RateLimiter::cleanup_old_entries();
        }
    });
}
