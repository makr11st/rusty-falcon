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
pub struct ExclusionsPeriodExclusionV1 {
    #[serde(rename = "applied_globally")]
    pub applied_globally: bool,
    #[serde(rename = "created_by")]
    pub created_by: String,
    #[serde(rename = "created_on")]
    pub created_on: String,
    #[serde(rename = "excluded_from", skip_serializing_if = "Option::is_none")]
    pub excluded_from: Option<Vec<String>>,
    #[serde(rename = "groups")]
    pub groups: Vec<crate::models::HostGroupsPeriodHostGroupV1>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "last_modified")]
    pub last_modified: String,
    #[serde(rename = "modified_by")]
    pub modified_by: String,
    #[serde(rename = "regexp_value")]
    pub regexp_value: String,
    #[serde(rename = "value")]
    pub value: String,
    #[serde(rename = "value_hash")]
    pub value_hash: String,
}

impl ExclusionsPeriodExclusionV1 {
    pub fn new(
        applied_globally: bool,
        created_by: String,
        created_on: String,
        groups: Vec<crate::models::HostGroupsPeriodHostGroupV1>,
        id: String,
        last_modified: String,
        modified_by: String,
        regexp_value: String,
        value: String,
        value_hash: String,
    ) -> ExclusionsPeriodExclusionV1 {
        ExclusionsPeriodExclusionV1 {
            applied_globally,
            created_by,
            created_on,
            excluded_from: None,
            groups,
            id,
            last_modified,
            modified_by,
            regexp_value,
            value,
            value_hash,
        }
    }
}
