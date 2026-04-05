use sqlx::PgPool;
use jsonwebtoken::{DecodingKey, EncodingKey};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub jwt_secret: Arc<str>,
    pub jwt_encoding_key: EncodingKey,
    pub jwt_decoding_key: DecodingKey,
}

impl AppState {
    pub async fn new(pool: PgPool, jwt_secret: String) -> Self {
        let jwt_secret_arc: Arc<str> = Arc::from(jwt_secret.as_str());
        let jwt_encoding_key = EncodingKey::from_secret(jwt_secret.as_bytes());
        let jwt_decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());
        
        Self {
            pool,
            jwt_secret: jwt_secret_arc,
            jwt_encoding_key,
            jwt_decoding_key,
        }
    }
}
