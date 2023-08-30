/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and examples, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation).     To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`.    Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: rolling
 *
 * Generated by: https://openapi-generator.tech
 */

use reqwest;

use super::{configuration, Error};
use crate::apis::ResponseContent;

/// struct for typed errors of method [`oauth2_access_token`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Oauth2AccessTokenError {
    Status400(crate::models::MsaPeriodReplyMetaOnly),
    Status403(crate::models::MsaPeriodReplyMetaOnly),
    Status429(crate::models::MsaPeriodReplyMetaOnly),
    Status500(crate::models::MsaPeriodReplyMetaOnly),
    UnknownValue(serde_json::Value),
}

/// struct for typed errors of method [`oauth2_revoke_token`]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Oauth2RevokeTokenError {
    Status400(crate::models::MsaPeriodReplyMetaOnly),
    Status403(crate::models::MsaPeriodReplyMetaOnly),
    Status429(crate::models::MsaPeriodReplyMetaOnly),
    Status500(crate::models::MsaPeriodReplyMetaOnly),
    UnknownValue(serde_json::Value),
}

pub async fn oauth2_access_token(
    configuration: &configuration::Configuration,
    client_id: &str,
    client_secret: &str,
    member_cid: Option<&str>,
) -> Result<crate::models::DomainPeriodAccessTokenResponseV1, Error<Oauth2AccessTokenError>> {
    let local_var_configuration = configuration;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/oauth2/token", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    if let Some(ref local_var_auth_conf) = local_var_configuration.basic_auth {
        local_var_req_builder = local_var_req_builder.basic_auth(
            local_var_auth_conf.0.to_owned(),
            local_var_auth_conf.1.to_owned(),
        );
    };
    let mut local_var_form_params = std::collections::HashMap::new();
    local_var_form_params.insert("client_id", client_id.to_string());
    local_var_form_params.insert("client_secret", client_secret.to_string());
    if let Some(local_var_param_value) = member_cid {
        local_var_form_params.insert("member_cid", local_var_param_value.to_string());
    }
    local_var_req_builder = local_var_req_builder.form(&local_var_form_params);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<Oauth2AccessTokenError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}

pub async fn oauth2_revoke_token(
    configuration: &configuration::Configuration,
    token: &str,
    client_id: Option<&str>,
) -> Result<crate::models::MsaPeriodReplyMetaOnly, Error<Oauth2RevokeTokenError>> {
    let local_var_configuration = configuration;

    let local_var_client = &local_var_configuration.client;

    let local_var_uri_str = format!("{}/oauth2/revoke", local_var_configuration.base_path);
    let mut local_var_req_builder =
        local_var_client.request(reqwest::Method::POST, local_var_uri_str.as_str());

    if let Some(ref local_var_user_agent) = local_var_configuration.user_agent {
        local_var_req_builder =
            local_var_req_builder.header(reqwest::header::USER_AGENT, local_var_user_agent.clone());
    }
    if let Some(ref local_var_auth_conf) = local_var_configuration.basic_auth {
        local_var_req_builder = local_var_req_builder.basic_auth(
            local_var_auth_conf.0.to_owned(),
            local_var_auth_conf.1.to_owned(),
        );
    };
    let mut local_var_form_params = std::collections::HashMap::new();
    if let Some(local_var_param_value) = client_id {
        local_var_form_params.insert("client_id", local_var_param_value.to_string());
    }
    local_var_form_params.insert("token", token.to_string());
    local_var_req_builder = local_var_req_builder.form(&local_var_form_params);

    let local_var_req = local_var_req_builder.build()?;
    let local_var_resp = local_var_client.execute(local_var_req).await?;

    let local_var_status = local_var_resp.status();
    let local_var_content = local_var_resp.text().await?;

    if !local_var_status.is_client_error() && !local_var_status.is_server_error() {
        serde_json::from_str(&local_var_content).map_err(Error::from)
    } else {
        let local_var_entity: Option<Oauth2RevokeTokenError> =
            serde_json::from_str(&local_var_content).ok();
        let local_var_error = ResponseContent {
            status: local_var_status,
            content: local_var_content,
            entity: local_var_entity,
        };
        Err(Error::ResponseError(local_var_error))
    }
}
