use std::env;

use super::FalconError;

#[derive(Debug, Clone)]
pub struct Credentials {
    pub client_id: String,
    pub client_secret: String,
    pub member_cid: Option<String>,
}

impl Credentials {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            member_cid: None,
        }
    }

    pub fn with_member_cid(mut self, member_cid: impl Into<String>) -> Self {
        self.member_cid = Some(member_cid.into());
        self
    }

    pub fn from_env() -> Result<Self, FalconError> {
        let client_id = env::var("FALCON_CLIENT_ID").map_err(|_| FalconError::MissingClientId)?;
        let client_secret =
            env::var("FALCON_CLIENT_SECRET").map_err(|_| FalconError::MissingClientSecret)?;
        let member_cid = env::var("FALCON_MEMBER_CID").ok();

        Ok(Self {
            client_id,
            client_secret,
            member_cid,
        })
    }
}
