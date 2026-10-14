use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("could not read key file: {0}")]
    KeyFile(String),

    #[error("failed to sign deploy: {0}")]
    Sign(String),

    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("gRPC call failed: {0}")]
    Rpc(#[from] tonic::Status),

    /// The server returned a `oneof message = ServiceError` arm. Carries
    /// the error strings exactly as sent.
    #[error("node returned ServiceError: {0}")]
    ServiceError(String),
}
