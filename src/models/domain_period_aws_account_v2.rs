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
pub struct DomainPeriodAwsAccountV2 {
    #[serde(rename = "CreatedAt")]
    pub created_at: String,
    #[serde(rename = "DeletedAt")]
    pub deleted_at: String,
    #[serde(rename = "ID")]
    pub id: i32,
    #[serde(rename = "UpdatedAt")]
    pub updated_at: String,
    /// 12 digit AWS provided unique identifier for the account.
    #[serde(rename = "account_id", skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    /// AWS account name
    #[serde(rename = "account_name", skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
    #[serde(rename = "account_type", skip_serializing_if = "Option::is_none")]
    pub account_type: Option<String>,
    #[serde(rename = "active_regions", skip_serializing_if = "Option::is_none")]
    pub active_regions: Option<Vec<String>>,
    /// AWS CloudTrail bucket name to store logs.
    #[serde(
        rename = "aws_cloudtrail_bucket_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub aws_cloudtrail_bucket_name: Option<String>,
    /// AWS CloudTrail region.
    #[serde(
        rename = "aws_cloudtrail_region",
        skip_serializing_if = "Option::is_none"
    )]
    pub aws_cloudtrail_region: Option<String>,
    /// AWS Eventbus ARN.
    #[serde(rename = "aws_eventbus_arn", skip_serializing_if = "Option::is_none")]
    pub aws_eventbus_arn: Option<String>,
    /// Permissions status returned via API.
    #[serde(rename = "aws_permissions_status")]
    pub aws_permissions_status: Vec<crate::models::DomainPeriodPermission>,
    #[serde(
        rename = "behavior_assessment_enabled",
        skip_serializing_if = "Option::is_none"
    )]
    pub behavior_assessment_enabled: Option<bool>,
    #[serde(rename = "cid", skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    #[serde(rename = "cloud_scopes", skip_serializing_if = "Option::is_none")]
    pub cloud_scopes: Option<Vec<crate::models::DomainPeriodCloudScope>>,
    #[serde(rename = "cloudformation_url", skip_serializing_if = "Option::is_none")]
    pub cloudformation_url: Option<String>,
    #[serde(rename = "conditions", skip_serializing_if = "Option::is_none")]
    pub conditions: Option<Vec<crate::models::DomainPeriodCondition>>,
    #[serde(rename = "cspm_enabled", skip_serializing_if = "Option::is_none")]
    pub cspm_enabled: Option<bool>,
    #[serde(rename = "d4c", skip_serializing_if = "Option::is_none")]
    pub d4c: Option<Box<crate::models::DomainPeriodAwsd4CAccountV1>>,
    #[serde(rename = "d4c_migrated", skip_serializing_if = "Option::is_none")]
    pub d4c_migrated: Option<bool>,
    #[serde(rename = "environment", skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(rename = "eventbus_name", skip_serializing_if = "Option::is_none")]
    pub eventbus_name: Option<String>,
    /// ID assigned for use with cross account IAM role access.
    #[serde(rename = "external_id", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    /// The full arn of the IAM role created in this account to control access.
    #[serde(rename = "iam_role_arn", skip_serializing_if = "Option::is_none")]
    pub iam_role_arn: Option<String>,
    #[serde(
        rename = "intermediate_role_arn",
        skip_serializing_if = "Option::is_none"
    )]
    pub intermediate_role_arn: Option<String>,
    #[serde(rename = "is_custom_rolename")]
    pub is_custom_rolename: bool,
    #[serde(rename = "is_master", skip_serializing_if = "Option::is_none")]
    pub is_master: Option<bool>,
    /// Up to 34 character AWS provided unique identifier for the organization.
    #[serde(rename = "organization_id", skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(
        rename = "remediation_cloudformation_url",
        skip_serializing_if = "Option::is_none"
    )]
    pub remediation_cloudformation_url: Option<String>,
    #[serde(rename = "remediation_region", skip_serializing_if = "Option::is_none")]
    pub remediation_region: Option<String>,
    #[serde(
        rename = "remediation_tou_accepted",
        skip_serializing_if = "Option::is_none"
    )]
    pub remediation_tou_accepted: Option<String>,
    /// 12 digit AWS provided unique identifier for the root account (of the organization this account belongs to).
    #[serde(rename = "root_account_id", skip_serializing_if = "Option::is_none")]
    pub root_account_id: Option<String>,
    #[serde(rename = "root_iam_role", skip_serializing_if = "Option::is_none")]
    pub root_iam_role: Option<bool>,
    #[serde(rename = "secondary_role_arn", skip_serializing_if = "Option::is_none")]
    pub secondary_role_arn: Option<String>,
    #[serde(rename = "sensor_management_enabled")]
    pub sensor_management_enabled: bool,
    #[serde(rename = "settings", skip_serializing_if = "Option::is_none")]
    pub settings: Option<serde_json::Value>,
    /// Account registration status.
    #[serde(rename = "status", skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(
        rename = "use_existing_cloudtrail",
        skip_serializing_if = "Option::is_none"
    )]
    pub use_existing_cloudtrail: Option<bool>,
    #[serde(rename = "valid", skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
}

impl DomainPeriodAwsAccountV2 {
    pub fn new(
        created_at: String,
        deleted_at: String,
        id: i32,
        updated_at: String,
        aws_permissions_status: Vec<crate::models::DomainPeriodPermission>,
        is_custom_rolename: bool,
        sensor_management_enabled: bool,
    ) -> DomainPeriodAwsAccountV2 {
        DomainPeriodAwsAccountV2 {
            created_at,
            deleted_at,
            id,
            updated_at,
            account_id: None,
            account_name: None,
            account_type: None,
            active_regions: None,
            aws_cloudtrail_bucket_name: None,
            aws_cloudtrail_region: None,
            aws_eventbus_arn: None,
            aws_permissions_status,
            behavior_assessment_enabled: None,
            cid: None,
            cloud_scopes: None,
            cloudformation_url: None,
            conditions: None,
            cspm_enabled: None,
            d4c: None,
            d4c_migrated: None,
            environment: None,
            eventbus_name: None,
            external_id: None,
            iam_role_arn: None,
            intermediate_role_arn: None,
            is_custom_rolename,
            is_master: None,
            organization_id: None,
            remediation_cloudformation_url: None,
            remediation_region: None,
            remediation_tou_accepted: None,
            root_account_id: None,
            root_iam_role: None,
            secondary_role_arn: None,
            sensor_management_enabled,
            settings: None,
            status: None,
            use_existing_cloudtrail: None,
            valid: None,
        }
    }
}
