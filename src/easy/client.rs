use std::env;
use crate::apis::{Error};
use crate::apis::configuration::{Configuration};
use crate::apis::oauth2_api::{oauth2_access_token, Oauth2AccessTokenError};

pub async fn new_client(creds: Credentials) -> Result<Configuration, Error<Oauth2AccessTokenError>> {
    let mut configuration = Configuration {
        ..Default::default()
    };

    let response = oauth2_access_token(&configuration, &creds.falcon_client_id, &creds.falcon_client_secret, None).await?;

    configuration.oauth_access_token = Some(response.access_token);
    return Ok(configuration);
}

pub struct Credentials {
    falcon_client_id: String,
    falcon_client_secret: String,
}

impl Credentials {
    pub fn from_env() -> Result<Credentials, CredentialsError> {
        let client_id = env::var("FALCON_CLIENT_ID")
            .map_err(|_| CredentialsError(format!("Missing FALCON_CLIENT_ID environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.")))?;

        let client_secret = env::var("FALCON_CLIENT_SECRET")
            .map_err(|_| CredentialsError(format!("Missing FALCON_CLIENT_SECRET environment variable. Please provide your OAuth2 API Client Secret for authentication with CrowdStrike Falcon platform. Establishing and retrieving OAuth2 API credentials can be performed at https://falcon.crowdstrike.com/support/api-clients-and-keys.")))?;

        return Ok(Credentials{
            falcon_client_id: client_id,
            falcon_client_secret: client_secret,
        });
    }
}

#[derive(Debug)]
pub struct CredentialsError(String);
