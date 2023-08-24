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
pub struct DomainPeriodCreateActionRequest {
    /// The level of detail in which the content will be delivered. It can be either 'standard' or 'enhanced'
    #[serde(rename = "content_format")]
    pub content_format: String,
    /// The time interval between the action's triggers. It can be one of the values: 'asap', 'daily' or 'weekly'
    #[serde(rename = "frequency")]
    pub frequency: String,
    /// The address list who will be notified by this action.
    #[serde(rename = "recipients")]
    pub recipients: Vec<String>,
    /// Whether to periodically trigger the action based on the frequency, even when there are no new matches for the associated monitoring rule
    #[serde(rename = "trigger_matchless")]
    pub trigger_matchless: bool,
    /// The action type. The only type currently supported is 'email'
    #[serde(rename = "type")]
    pub r#type: String,
}

impl DomainPeriodCreateActionRequest {
    pub fn new(
        content_format: String,
        frequency: String,
        recipients: Vec<String>,
        trigger_matchless: bool,
        r#type: String,
    ) -> DomainPeriodCreateActionRequest {
        DomainPeriodCreateActionRequest {
            content_format,
            frequency,
            recipients,
            trigger_matchless,
            r#type,
        }
    }
}
