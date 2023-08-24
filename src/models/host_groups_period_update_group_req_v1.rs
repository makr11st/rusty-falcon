/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and examples, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation).     To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`.    Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: 2023-08-23T23:00:01Z
 *
 * Generated by: https://openapi-generator.tech
 */

/// HostGroupsPeriodUpdateGroupReqV1 : A specific group to be updated

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct HostGroupsPeriodUpdateGroupReqV1 {
    /// The new assignment rule of the group. Note: If the group type is static, this field cannot be updated manually
    #[serde(rename = "assignment_rule", skip_serializing_if = "Option::is_none")]
    pub assignment_rule: Option<String>,
    /// The new description of the group
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The id of the group to update
    #[serde(rename = "id")]
    pub id: String,
    /// The new name of the group
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl HostGroupsPeriodUpdateGroupReqV1 {
    /// A specific group to be updated
    pub fn new(id: String) -> HostGroupsPeriodUpdateGroupReqV1 {
        HostGroupsPeriodUpdateGroupReqV1 {
            assignment_rule: None,
            description: None,
            id,
            name: None,
        }
    }
}
