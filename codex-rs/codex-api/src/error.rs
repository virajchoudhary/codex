use crate::rate_limits::RateLimitError;
use codex_client::TransportError;
use codex_http_client::RetryAfter;
use codex_protocol::error::ResponseIncompleteError;
use codex_protocol::protocol::MisalignmentErrorDetails;
use http::StatusCode;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("api error {status}: {message}")]
    Api { status: StatusCode, message: String },
    #[error("stream error: {0}")]
    Stream(String),
    #[error("stream error: Incomplete response returned, reason: content_filter")]
    ContentFilter,
    #[error(transparent)]
    ResponseIncomplete(Box<ResponseIncompleteError>),
    #[error("context window exceeded")]
    ContextWindowExceeded,
    #[error("quota exceeded")]
    QuotaExceeded,
    #[error("usage not included")]
    UsageNotIncluded,
    #[error("retryable error: {message}")]
    Retryable {
        message: String,
        retry_after: Option<RetryAfter>,
    },
    #[error("rate limit exceeded: {message}")]
    RateLimitExceeded {
        message: String,
        retry_after: Option<RetryAfter>,
    },
    #[error("rate limit: {0}")]
    RateLimit(String),
    #[error("invalid request: {message}")]
    InvalidRequest { message: String },
    #[error("invalid prompt: {message}")]
    InvalidPrompt { message: String },
    #[error("cyber policy: {message}")]
    CyberPolicy { message: String },
    #[error("bio policy: {message}")]
    BioPolicy { message: String },
    #[error("misalignment policy violation: {message}")]
    MisalignmentPolicyViolation {
        message: String,
        misalignment: Option<MisalignmentErrorDetails>,
    },
    #[error("Flex capacity unavailable.")]
    FlexUnavailable,
    #[error("server overloaded")]
    ServerOverloaded { retry_after: Option<RetryAfter> },
}

impl From<RateLimitError> for ApiError {
    fn from(err: RateLimitError) -> Self {
        Self::RateLimit(err.to_string())
    }
}

pub(crate) fn parse_flex_unavailable(error: &Value) -> Option<ApiError> {
    (error.get("code").and_then(Value::as_str) == Some("flex_unavailable"))
        .then_some(ApiError::FlexUnavailable)
}

pub(crate) const INVALID_ENCRYPTED_CONTENT_ERROR_CODE: &str = "invalid_encrypted_content";
const INVALID_ENCRYPTED_CONTENT_ERROR_MESSAGE: &str =
    "The service could not verify encrypted content in this request.";

pub(crate) fn invalid_encrypted_content_error() -> ApiError {
    ApiError::InvalidRequest {
        message: INVALID_ENCRYPTED_CONTENT_ERROR_MESSAGE.to_string(),
    }
}

pub(crate) fn parse_invalid_encrypted_content(error: &Value) -> Option<ApiError> {
    (error.get("code").and_then(Value::as_str) == Some(INVALID_ENCRYPTED_CONTENT_ERROR_CODE))
        .then(invalid_encrypted_content_error)
}

impl From<crate::AuthError> for ApiError {
    fn from(error: crate::AuthError) -> Self {
        Self::Transport(error.into())
    }
}
