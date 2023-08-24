/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and examples, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation).     To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`.    Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: 2023-08-23T23:00:01Z
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct ApiPeriodCustomerSettingsResourceV1 {
    #[serde(rename = "max_active_tokens", skip_serializing_if = "Option::is_none")]
    pub max_active_tokens: Option<i32>,
    #[serde(rename = "tokens_required")]
    pub tokens_required: bool,
}

impl ApiPeriodCustomerSettingsResourceV1 {
    pub fn new(tokens_required: bool) -> ApiPeriodCustomerSettingsResourceV1 {
        ApiPeriodCustomerSettingsResourceV1 {
            max_active_tokens: None,
            tokens_required,
        }
    }
}
