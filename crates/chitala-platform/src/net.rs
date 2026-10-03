//! Network (v20 §4: transport is a plugin).
//!
//! Only adapters use the network today (the Home Assistant bridge). A request
//! that reaches the server returns `Ok` whatever the HTTP status; transport
//! failures are [`crate::PlatformError::Unreachable`] or `Timeout`.

use std::time::Duration;

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait NetworkTransport: Send + Sync {
    fn http(&self, request: &HttpRequest) -> Result<HttpResponse>;
}
