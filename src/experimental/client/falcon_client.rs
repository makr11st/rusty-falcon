use std::{ops::Deref, sync::Arc, time::Duration};

use super::{Credentials, FalconCloud, FalconError};
use crate::experimental::apis::{
    Api, ApiClient,
    configuration::Configuration,
    oauth2_api::{Oauth2AccessTokenParams, Oauth2Api, Oauth2ApiClient},
};

pub struct FalconClient {
    inner: ApiClient,
}

impl FalconClient {
    pub async fn from_env() -> Result<Self, FalconError> {
        FalconClientBuilder::new()
            .credentials_from_env()?
            .cloud_from_env()?
            .build()
            .await
    }

    pub async fn new(credentials: Credentials, cloud: FalconCloud) -> Result<Self, FalconError> {
        FalconClientBuilder::new()
            .credentials(credentials)
            .cloud(cloud)
            .build()
            .await
    }

    pub fn builder() -> FalconClientBuilder {
        FalconClientBuilder::new()
    }
}

impl Deref for FalconClient {
    type Target = dyn Api;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct FalconClientBuilder {
    credentials: Option<Credentials>,
    cloud: Option<FalconCloud>,
    http_client: Option<reqwest::Client>,
    user_agent: Option<String>,
    timeout: Option<Duration>,
}

impl FalconClientBuilder {
    pub fn new() -> Self {
        Self {
            credentials: None,
            cloud: None,
            http_client: None,
            user_agent: None,
            timeout: None,
        }
    }

    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn credentials_from_env(mut self) -> Result<Self, FalconError> {
        self.credentials = Some(Credentials::from_env()?);
        Ok(self)
    }

    pub fn cloud(mut self, cloud: FalconCloud) -> Self {
        self.cloud = Some(cloud);
        self
    }

    pub fn cloud_from_env(mut self) -> Result<Self, FalconError> {
        self.cloud = Some(FalconCloud::from_env()?);
        Ok(self)
    }

    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub async fn build(self) -> Result<FalconClient, FalconError> {
        let credentials = self.credentials.ok_or(FalconError::MissingClientId)?;
        let cloud = self.cloud.unwrap_or_default();
        let base_url = cloud.base_url();

        let http_client = match self.http_client {
            Some(client) => client,
            None => {
                let mut builder = reqwest::Client::builder();
                if let Some(timeout) = self.timeout {
                    builder = builder.timeout(timeout);
                }
                builder.build().map_err(FalconError::Request)?
            }
        };

        let user_agent = self
            .user_agent
            .unwrap_or_else(|| format!("rusty-falcon-experimental/{}", env!("CARGO_PKG_VERSION")));

        let auth_config = Arc::new(Configuration {
            base_path: base_url.clone(),
            user_agent: Some(user_agent.clone()),
            client: http_client.clone(),
            ..Configuration::default()
        });

        let oauth_client = Oauth2ApiClient::new(auth_config);
        let token_response = oauth_client
            .oauth2_access_token(Oauth2AccessTokenParams {
                client_id: credentials.client_id,
                client_secret: credentials.client_secret,
                member_cid: credentials.member_cid,
            })
            .await
            .map_err(|e| FalconError::Authentication(e.to_string()))?;

        let access_token = token_response
            .access_token
            .ok_or_else(|| FalconError::Authentication("no access token in response".into()))?;

        let config = Arc::new(Configuration {
            base_path: base_url,
            user_agent: Some(user_agent),
            client: http_client,
            bearer_access_token: Some(access_token),
            ..Configuration::default()
        });

        Ok(FalconClient {
            inner: ApiClient::new(config),
        })
    }
}

impl Default for FalconClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}
