//! Simple rate-limit helper for Graph API calls.
//!
//! Graph enforces per-resource throttling and returns HTTP 429 with a
//! Retry-After header. This module provides a basic backoff loop and
//! a configurable per-request delay for bulk operations.

use std::time::Duration;

/// Milliseconds to sleep between sequential Graph calls in bulk operations.
const DEFAULT_DELAY_MS: u64 = 100;

/// Sleep for the default inter-request delay.
/// Call this between iterations in bulk commands (e.g. signin:bulk).
pub fn inter_request_delay() {
    std::thread::sleep(Duration::from_millis(DEFAULT_DELAY_MS));
}

/// Sleep for `seconds` before retrying after a 429 response.
/// `seconds` should come from the Retry-After response header.
pub fn retry_after(seconds: u64) {
    eprintln!("[throttle] 429 received — waiting {}s before retry…", seconds);
    std::thread::sleep(Duration::from_secs(seconds));
}
