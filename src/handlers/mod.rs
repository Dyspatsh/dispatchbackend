pub mod storage;
pub mod block;
pub mod rate_limiter;
pub mod files;

// Re-export all handlers
pub use storage::get_storage_info;
pub use block::{block_user, unblock_user, get_blocked_users, is_blocked_by};
pub use rate_limiter::{search_users, check_user_status, get_public_key_by_username};
pub use files::{
    upload_file, list_pending_files, list_sent_files, list_received_files,
    accept_file, decline_file, cancel_file, download_file
};
