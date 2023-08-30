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
pub struct DomainPeriodPolicyInfo {
    #[serde(rename = "CreatedAt")]
    pub created_at: String,
    #[serde(rename = "DeletedAt")]
    pub deleted_at: String,
    #[serde(rename = "ID")]
    pub id: i32,
    #[serde(rename = "UpdatedAt")]
    pub updated_at: String,
    #[serde(rename = "alert_logic", skip_serializing_if = "Option::is_none")]
    pub alert_logic: Option<String>,
    #[serde(rename = "api_command", skip_serializing_if = "Option::is_none")]
    pub api_command: Option<String>,
    #[serde(rename = "asset_type_id", skip_serializing_if = "Option::is_none")]
    pub asset_type_id: Option<i32>,
    #[serde(rename = "attack_tool", skip_serializing_if = "Option::is_none")]
    pub attack_tool: Option<String>,
    #[serde(
        rename = "attack_tool_command",
        skip_serializing_if = "Option::is_none"
    )]
    pub attack_tool_command: Option<String>,
    #[serde(rename = "attack_types", skip_serializing_if = "Option::is_none")]
    pub attack_types: Option<Vec<String>>,
    #[serde(rename = "cis_benchmark_ids", skip_serializing_if = "Option::is_none")]
    pub cis_benchmark_ids: Option<Vec<i32>>,
    #[serde(rename = "cli_command", skip_serializing_if = "Option::is_none")]
    pub cli_command: Option<String>,
    #[serde(rename = "cloud_asset_type", skip_serializing_if = "Option::is_none")]
    pub cloud_asset_type: Option<String>,
    #[serde(rename = "cloud_document", skip_serializing_if = "Option::is_none")]
    pub cloud_document: Option<String>,
    #[serde(rename = "cloud_platform", skip_serializing_if = "Option::is_none")]
    pub cloud_platform: Option<i32>,
    #[serde(
        rename = "cloud_platform_type",
        skip_serializing_if = "Option::is_none"
    )]
    pub cloud_platform_type: Option<String>,
    #[serde(rename = "cloud_service", skip_serializing_if = "Option::is_none")]
    pub cloud_service: Option<i32>,
    #[serde(
        rename = "cloud_service_friendly",
        skip_serializing_if = "Option::is_none"
    )]
    pub cloud_service_friendly: Option<String>,
    #[serde(
        rename = "cloud_service_subtype",
        skip_serializing_if = "Option::is_none"
    )]
    pub cloud_service_subtype: Option<String>,
    #[serde(rename = "cloud_service_type", skip_serializing_if = "Option::is_none")]
    pub cloud_service_type: Option<String>,
    #[serde(rename = "confidence", skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(rename = "default_severity", skip_serializing_if = "Option::is_none")]
    pub default_severity: Option<String>,
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "event_type", skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    #[serde(rename = "fql_policy", skip_serializing_if = "Option::is_none")]
    pub fql_policy: Option<String>,
    #[serde(rename = "internal_only", skip_serializing_if = "Option::is_none")]
    pub internal_only: Option<bool>,
    #[serde(rename = "is_enabled")]
    pub is_enabled: bool,
    #[serde(rename = "is_remediable")]
    pub is_remediable: bool,
    #[serde(
        rename = "mitre_attack_cloud_matrix",
        skip_serializing_if = "Option::is_none"
    )]
    pub mitre_attack_cloud_matrix: Option<String>,
    #[serde(
        rename = "mitre_attack_cloud_subtype",
        skip_serializing_if = "Option::is_none"
    )]
    pub mitre_attack_cloud_subtype: Option<String>,
    #[serde(rename = "nist_benchmark_ids", skip_serializing_if = "Option::is_none")]
    pub nist_benchmark_ids: Option<Vec<i32>>,
    #[serde(rename = "pci_benchmark_ids", skip_serializing_if = "Option::is_none")]
    pub pci_benchmark_ids: Option<Vec<i32>>,
    #[serde(
        rename = "policy_confidence_score",
        skip_serializing_if = "Option::is_none"
    )]
    pub policy_confidence_score: Option<i32>,
    #[serde(rename = "policy_fail_query", skip_serializing_if = "Option::is_none")]
    pub policy_fail_query: Option<String>,
    #[serde(rename = "policy_pass_query", skip_serializing_if = "Option::is_none")]
    pub policy_pass_query: Option<String>,
    #[serde(rename = "policy_remediation", skip_serializing_if = "Option::is_none")]
    pub policy_remediation: Option<String>,
    #[serde(rename = "policy_severity", skip_serializing_if = "Option::is_none")]
    pub policy_severity: Option<i32>,
    #[serde(
        rename = "policy_severity_score",
        skip_serializing_if = "Option::is_none"
    )]
    pub policy_severity_score: Option<i32>,
    #[serde(rename = "policy_statement", skip_serializing_if = "Option::is_none")]
    pub policy_statement: Option<String>,
    #[serde(rename = "policy_type", skip_serializing_if = "Option::is_none")]
    pub policy_type: Option<String>,
    #[serde(
        rename = "remediation_summary",
        skip_serializing_if = "Option::is_none"
    )]
    pub remediation_summary: Option<String>,
    #[serde(rename = "soc2_benchmark_ids", skip_serializing_if = "Option::is_none")]
    pub soc2_benchmark_ids: Option<Vec<i32>>,
    #[serde(rename = "tactic", skip_serializing_if = "Option::is_none")]
    pub tactic: Option<String>,
    #[serde(rename = "tactic_id", skip_serializing_if = "Option::is_none")]
    pub tactic_id: Option<String>,
    #[serde(rename = "tactic_url", skip_serializing_if = "Option::is_none")]
    pub tactic_url: Option<String>,
    #[serde(rename = "technique", skip_serializing_if = "Option::is_none")]
    pub technique: Option<String>,
    #[serde(rename = "technique_id", skip_serializing_if = "Option::is_none")]
    pub technique_id: Option<String>,
    #[serde(rename = "technique_url", skip_serializing_if = "Option::is_none")]
    pub technique_url: Option<String>,
}

impl DomainPeriodPolicyInfo {
    pub fn new(
        created_at: String,
        deleted_at: String,
        id: i32,
        updated_at: String,
        is_enabled: bool,
        is_remediable: bool,
    ) -> DomainPeriodPolicyInfo {
        DomainPeriodPolicyInfo {
            created_at,
            deleted_at,
            id,
            updated_at,
            alert_logic: None,
            api_command: None,
            asset_type_id: None,
            attack_tool: None,
            attack_tool_command: None,
            attack_types: None,
            cis_benchmark_ids: None,
            cli_command: None,
            cloud_asset_type: None,
            cloud_document: None,
            cloud_platform: None,
            cloud_platform_type: None,
            cloud_service: None,
            cloud_service_friendly: None,
            cloud_service_subtype: None,
            cloud_service_type: None,
            confidence: None,
            default_severity: None,
            description: None,
            event_type: None,
            fql_policy: None,
            internal_only: None,
            is_enabled,
            is_remediable,
            mitre_attack_cloud_matrix: None,
            mitre_attack_cloud_subtype: None,
            nist_benchmark_ids: None,
            pci_benchmark_ids: None,
            policy_confidence_score: None,
            policy_fail_query: None,
            policy_pass_query: None,
            policy_remediation: None,
            policy_severity: None,
            policy_severity_score: None,
            policy_statement: None,
            policy_type: None,
            remediation_summary: None,
            soc2_benchmark_ids: None,
            tactic: None,
            tactic_id: None,
            tactic_url: None,
            technique: None,
            technique_id: None,
            technique_url: None,
        }
    }
}
