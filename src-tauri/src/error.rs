use serde::Serialize;
use thiserror::Error;

/// Application-level errors
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Not connected to Active Directory")]
    NotConnected,

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("LDAP error: {0}")]
    LdapError(String),

    #[error("Object not found: {0}")]
    ObjectNotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid tier: {0}")]
    InvalidTier(String),

    #[error("OU not found: {0}")]
    OuNotFound(String),

    #[error("Group not found: {0}")]
    GroupNotFound(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("GPO error: {0}")]
    GpoError(String),

    #[error("Operation failed: {0}")]
    OperationFailed(String),

    #[error("Tier not initialized: {0}")]
    TierNotInitialized(String),

    #[error("Windows API error: {0}")]
    WindowsError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Serializable error for Tauri commands
#[derive(Debug, Serialize)]
pub struct CommandError {
    pub code: String,
    pub message: String,
}

impl From<AppError> for CommandError {
    fn from(err: AppError) -> Self {
        let code = match &err {
            AppError::NotConnected => "NOT_CONNECTED",
            AppError::AuthenticationFailed(_) => "AUTH_FAILED",
            AppError::LdapError(_) => "LDAP_ERROR",
            AppError::ObjectNotFound(_) => "NOT_FOUND",
            AppError::PermissionDenied(_) => "PERMISSION_DENIED",
            AppError::InvalidTier(_) => "INVALID_TIER",
            AppError::OuNotFound(_) => "OU_NOT_FOUND",
            AppError::GroupNotFound(_) => "GROUP_NOT_FOUND",
            AppError::ConfigError(_) => "CONFIG_ERROR",
            AppError::GpoError(_) => "GPO_ERROR",
            AppError::OperationFailed(_) => "OPERATION_FAILED",
            AppError::TierNotInitialized(_) => "TIER_NOT_INITIALIZED",
            AppError::WindowsError(_) => "WINDOWS_ERROR",
            AppError::IoError(_) => "IO_ERROR",
            AppError::SerializationError(_) => "SERIALIZATION_ERROR",
        };

        CommandError {
            code: code.to_string(),
            message: err.to_string(),
        }
    }
}

// Make AppError serializable for Tauri
impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let cmd_error = CommandError {
            code: self.error_code().to_string(),
            message: self.to_string(),
        };
        cmd_error.serialize(serializer)
    }
}

impl AppError {
    fn error_code(&self) -> &'static str {
        match self {
            AppError::NotConnected => "NOT_CONNECTED",
            AppError::AuthenticationFailed(_) => "AUTH_FAILED",
            AppError::LdapError(_) => "LDAP_ERROR",
            AppError::ObjectNotFound(_) => "NOT_FOUND",
            AppError::PermissionDenied(_) => "PERMISSION_DENIED",
            AppError::InvalidTier(_) => "INVALID_TIER",
            AppError::OuNotFound(_) => "OU_NOT_FOUND",
            AppError::GroupNotFound(_) => "GROUP_NOT_FOUND",
            AppError::ConfigError(_) => "CONFIG_ERROR",
            AppError::GpoError(_) => "GPO_ERROR",
            AppError::OperationFailed(_) => "OPERATION_FAILED",
            AppError::TierNotInitialized(_) => "TIER_NOT_INITIALIZED",
            AppError::WindowsError(_) => "WINDOWS_ERROR",
            AppError::IoError(_) => "IO_ERROR",
            AppError::SerializationError(_) => "SERIALIZATION_ERROR",
        }
    }
}

impl From<String> for AppError {
    fn from(s: String) -> Self {
        AppError::OperationFailed(s)
    }
}

pub type AppResult<T> = Result<T, AppError>;
