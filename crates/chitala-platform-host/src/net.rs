//! HTTP over `ureq`. Any HTTP status is a response; only transport failures
//! are errors.

use std::io::Read;
use std::time::Duration;

use chitala_platform::{HttpRequest, HttpResponse, NetworkTransport, PlatformError, Result};

/// Response bodies larger than this are refused (adapter replies are small).
pub const MAX_BODY: u64 = 1024 * 1024;

pub struct UreqNetwork;

fn body_of(r: ureq::Response) -> Result<HttpResponse> {
    let status = r.status();
    let mut body = Vec::new();
    r.into_reader().take(MAX_BODY + 1).read_to_end(&mut body)?;
    if body.len() as u64 > MAX_BODY {
        return Err(PlatformError::Invalid("response body too large".into()));
    }
    Ok(HttpResponse { status, body })
}

impl NetworkTransport for UreqNetwork {
    fn http(&self, req: &HttpRequest) -> Result<HttpResponse> {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(req.timeout.min(Duration::from_secs(3)))
            .timeout(req.timeout)
            .redirects(0)
            .build();
        let mut call = agent.request(&req.method, &req.url);
        for (k, v) in &req.headers {
            call = call.set(k, v);
        }
        let result = match &req.body {
            Some(b) => call.send_bytes(b),
            None => call.call(),
        };
        match result {
            Ok(r) | Err(ureq::Error::Status(_, r)) => body_of(r),
            Err(ureq::Error::Transport(t)) => Err(PlatformError::Unreachable(t.kind().to_string())),
        }
    }
}
