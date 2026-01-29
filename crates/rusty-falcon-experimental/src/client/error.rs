use std::env::VarError;

#[derive(Debug)]
pub enum FalconError {
    MissingClientId,
    MissingClientSecret,
    InvalidCloud(String),
    MissingCloudEnv,
    Authentication(String),
    Api(String),
    Request(reqwest::Error),
}

impl std::fmt::Display for FalconError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingClientId => write!(f, "FALCON_CLIENT_ID environment variable not set"),
            Self::MissingClientSecret => {
                write!(f, "FALCON_CLIENT_SECRET environment variable not set")
            }
            Self::InvalidCloud(cloud) => write!(f, "invalid cloud region: {cloud}"),
            Self::MissingCloudEnv => write!(f, "FALCON_CLOUD environment variable not set"),
            Self::Authentication(msg) => write!(f, "authentication failed: {msg}"),
            Self::Api(msg) => write!(f, "API error: {msg}"),
            Self::Request(e) => write!(f, "request error: {e}"),
        }
    }
}

impl std::error::Error for FalconError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(e) => Some(e),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for FalconError {
    fn from(e: reqwest::Error) -> Self {
        Self::Request(e)
    }
}

impl From<VarError> for FalconError {
    fn from(_: VarError) -> Self {
        Self::MissingCloudEnv
    }
}
