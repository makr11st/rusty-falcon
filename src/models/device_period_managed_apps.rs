/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and examples, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation).     To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`.    Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: 2023-08-08T23:00:01Z
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct DevicePeriodManagedApps {
    #[serde(rename = "airlock", skip_serializing_if = "Option::is_none")]
    pub airlock: Option<Box<crate::models::DevicePeriodManagedApp>>,
    #[serde(rename = "automox", skip_serializing_if = "Option::is_none")]
    pub automox: Option<Box<crate::models::DevicePeriodManagedApp>>,
    #[serde(
        rename = "aws-verified-access",
        skip_serializing_if = "Option::is_none"
    )]
    pub aws_verified_access: Option<Box<crate::models::DevicePeriodManagedApp>>,
    #[serde(
        rename = "identity-protection",
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_protection: Option<Box<crate::models::DevicePeriodManagedApp>>,
    #[serde(rename = "jumpcloud", skip_serializing_if = "Option::is_none")]
    pub jumpcloud: Option<Box<crate::models::DevicePeriodManagedApp>>,
    #[serde(rename = "netskope", skip_serializing_if = "Option::is_none")]
    pub netskope: Option<Box<crate::models::DevicePeriodManagedApp>>,
}

impl DevicePeriodManagedApps {
    pub fn new() -> DevicePeriodManagedApps {
        DevicePeriodManagedApps {
            airlock: None,
            automox: None,
            aws_verified_access: None,
            identity_protection: None,
            jumpcloud: None,
            netskope: None,
        }
    }
}
