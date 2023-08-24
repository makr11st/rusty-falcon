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
pub struct FalconxPeriodMitreAttack {
    #[serde(rename = "attack_id", skip_serializing_if = "Option::is_none")]
    pub attack_id: Option<String>,
    #[serde(rename = "attack_id_wiki", skip_serializing_if = "Option::is_none")]
    pub attack_id_wiki: Option<String>,
    #[serde(
        rename = "informative_identifiers",
        skip_serializing_if = "Option::is_none"
    )]
    pub informative_identifiers: Option<Vec<String>>,
    #[serde(
        rename = "malicious_identifiers",
        skip_serializing_if = "Option::is_none"
    )]
    pub malicious_identifiers: Option<Vec<String>>,
    #[serde(rename = "parent", skip_serializing_if = "Option::is_none")]
    pub parent: Option<Box<crate::models::FalconxPeriodMitreAttackParent>>,
    #[serde(
        rename = "suspicious_identifiers",
        skip_serializing_if = "Option::is_none"
    )]
    pub suspicious_identifiers: Option<Vec<String>>,
    #[serde(rename = "tactic", skip_serializing_if = "Option::is_none")]
    pub tactic: Option<String>,
    #[serde(rename = "technique", skip_serializing_if = "Option::is_none")]
    pub technique: Option<String>,
}

impl FalconxPeriodMitreAttack {
    pub fn new() -> FalconxPeriodMitreAttack {
        FalconxPeriodMitreAttack {
            attack_id: None,
            attack_id_wiki: None,
            informative_identifiers: None,
            malicious_identifiers: None,
            parent: None,
            suspicious_identifiers: None,
            tactic: None,
            technique: None,
        }
    }
}
