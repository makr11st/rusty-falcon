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
pub struct DetectsPeriodAlert {
    #[serde(rename = "agent_id", skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(rename = "aggregate_id", skip_serializing_if = "Option::is_none")]
    pub aggregate_id: Option<String>,
    #[serde(rename = "assigned_to_name", skip_serializing_if = "Option::is_none")]
    pub assigned_to_name: Option<String>,
    #[serde(rename = "assigned_to_uid", skip_serializing_if = "Option::is_none")]
    pub assigned_to_uid: Option<String>,
    #[serde(rename = "assigned_to_uuid", skip_serializing_if = "Option::is_none")]
    pub assigned_to_uuid: Option<String>,
    #[serde(rename = "cid", skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    #[serde(rename = "composite_id", skip_serializing_if = "Option::is_none")]
    pub composite_id: Option<String>,
    #[serde(rename = "confidence", skip_serializing_if = "Option::is_none")]
    pub confidence: Option<i32>,
    #[serde(rename = "crawl_edge_ids", skip_serializing_if = "Option::is_none")]
    pub crawl_edge_ids: Option<::std::collections::HashMap<String, Vec<String>>>,
    #[serde(rename = "crawl_vertex_ids", skip_serializing_if = "Option::is_none")]
    pub crawl_vertex_ids: Option<::std::collections::HashMap<String, Vec<String>>>,
    #[serde(rename = "crawled_timestamp", skip_serializing_if = "Option::is_none")]
    pub crawled_timestamp: Option<String>,
    #[serde(rename = "created_timestamp", skip_serializing_if = "Option::is_none")]
    pub created_timestamp: Option<String>,
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "display_name", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "email_sent", skip_serializing_if = "Option::is_none")]
    pub email_sent: Option<bool>,
    #[serde(rename = "es_doc_id", skip_serializing_if = "Option::is_none")]
    pub es_doc_id: Option<String>,
    #[serde(rename = "es_doc_version", skip_serializing_if = "Option::is_none")]
    pub es_doc_version: Option<i64>,
    #[serde(rename = "es_routing_id", skip_serializing_if = "Option::is_none")]
    pub es_routing_id: Option<String>,
    #[serde(rename = "external", skip_serializing_if = "Option::is_none")]
    pub external: Option<bool>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "objective", skip_serializing_if = "Option::is_none")]
    pub objective: Option<String>,
    #[serde(rename = "pattern_id", skip_serializing_if = "Option::is_none")]
    pub pattern_id: Option<i32>,
    #[serde(rename = "platform", skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(rename = "product", skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(rename = "scenario", skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(rename = "severity", skip_serializing_if = "Option::is_none")]
    pub severity: Option<i32>,
    #[serde(rename = "show_in_ui", skip_serializing_if = "Option::is_none")]
    pub show_in_ui: Option<bool>,
    #[serde(rename = "status", skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "tactic", skip_serializing_if = "Option::is_none")]
    pub tactic: Option<String>,
    #[serde(rename = "tactic_id", skip_serializing_if = "Option::is_none")]
    pub tactic_id: Option<String>,
    #[serde(rename = "tags", skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(rename = "technique", skip_serializing_if = "Option::is_none")]
    pub technique: Option<String>,
    #[serde(rename = "technique_id", skip_serializing_if = "Option::is_none")]
    pub technique_id: Option<String>,
    #[serde(rename = "timestamp", skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "updated_timestamp", skip_serializing_if = "Option::is_none")]
    pub updated_timestamp: Option<String>,
}

impl DetectsPeriodAlert {
    pub fn new(id: String, r#type: String) -> DetectsPeriodAlert {
        DetectsPeriodAlert {
            agent_id: None,
            aggregate_id: None,
            assigned_to_name: None,
            assigned_to_uid: None,
            assigned_to_uuid: None,
            cid: None,
            composite_id: None,
            confidence: None,
            crawl_edge_ids: None,
            crawl_vertex_ids: None,
            crawled_timestamp: None,
            created_timestamp: None,
            description: None,
            display_name: None,
            email_sent: None,
            es_doc_id: None,
            es_doc_version: None,
            es_routing_id: None,
            external: None,
            id,
            name: None,
            objective: None,
            pattern_id: None,
            platform: None,
            product: None,
            scenario: None,
            severity: None,
            show_in_ui: None,
            status: None,
            tactic: None,
            tactic_id: None,
            tags: None,
            technique: None,
            technique_id: None,
            timestamp: None,
            r#type,
            updated_timestamp: None,
        }
    }
}
