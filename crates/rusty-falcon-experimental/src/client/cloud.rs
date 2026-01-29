use std::str::FromStr;

use super::FalconError;

#[derive(Debug, Clone, Copy, Default)]
pub enum FalconCloud {
    #[default]
    Us1,
    Us2,
    Eu1,
    UsGov1,
}

impl FalconCloud {
    fn host(self) -> &'static str {
        match self {
            Self::Us1 => "api.crowdstrike.com",
            Self::Us2 => "api.us-2.crowdstrike.com",
            Self::Eu1 => "api.eu-1.crowdstrike.com",
            Self::UsGov1 => "api.laggar.gcw.crowdstrike.com",
        }
    }

    pub fn base_url(self) -> String {
        format!("https://{}", self.host())
    }

    pub fn from_env() -> Result<Self, FalconError> {
        let cloud_str = std::env::var("FALCON_CLOUD").map_err(|_| FalconError::MissingCloudEnv)?;
        Self::from_str(cloud_str.as_str())
    }
}

impl FromStr for FalconCloud {
    type Err = FalconError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "us-1" => Ok(Self::Us1),
            "us-2" => Ok(Self::Us2),
            "eu-1" => Ok(Self::Eu1),
            "us-gov-1" => Ok(Self::UsGov1),
            _ => Err(FalconError::InvalidCloud(s.to_string())),
        }
    }
}
