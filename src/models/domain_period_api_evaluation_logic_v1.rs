/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and examples, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation).     To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`.    Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: rolling
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct DomainPeriodApiEvaluationLogicV1 {
    /// Refers to an asset identifier
    #[serde(rename = "aid", skip_serializing_if = "Option::is_none")]
    pub aid: Option<String>,
    /// Refers to a customer identifier
    #[serde(rename = "cid", skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// Refers to a point in time when evaluation logic data was created in the system
    #[serde(rename = "created_timestamp", skip_serializing_if = "Option::is_none")]
    pub created_timestamp: Option<String>,
    /// Refers to a label given to the entity that provided this data
    #[serde(rename = "data_provider", skip_serializing_if = "Option::is_none")]
    pub data_provider: Option<String>,
    #[serde(rename = "host_info", skip_serializing_if = "Option::is_none")]
    pub host_info: Option<Box<crate::models::DomainPeriodApiEvaluationLogicHostInfoV1>>,
    /// Contains a unique identifier for the evaluation logic
    #[serde(rename = "id")]
    pub id: String,
    /// Refers to the actual evaluation logic data
    #[serde(rename = "logic", skip_serializing_if = "Option::is_none")]
    pub logic: Option<Vec<crate::models::DomainPeriodApiEvaluationLogicItemV1>>,
    /// Refers to the identifier of the scanner that generated the evaluation logic
    #[serde(rename = "scanner_id", skip_serializing_if = "Option::is_none")]
    pub scanner_id: Option<String>,
    /// Refers to a point in time when evaluation logic data was updated in the system
    #[serde(rename = "updated_timestamp", skip_serializing_if = "Option::is_none")]
    pub updated_timestamp: Option<String>,
}

impl DomainPeriodApiEvaluationLogicV1 {
    pub fn new(id: String) -> DomainPeriodApiEvaluationLogicV1 {
        DomainPeriodApiEvaluationLogicV1 {
            aid: None,
            cid: None,
            created_timestamp: None,
            data_provider: None,
            host_info: None,
            id,
            logic: None,
            scanner_id: None,
            updated_timestamp: None,
        }
    }
}
