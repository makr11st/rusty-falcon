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
pub struct MessagesPeriodCase {
    #[serde(rename = "aids")]
    pub aids: Vec<String>,
    #[serde(rename = "assigner")]
    pub assigner: Box<crate::models::MessagesPeriodAuthor>,
    #[serde(rename = "attachments")]
    pub attachments: Vec<crate::models::MessagesPeriodAttachment>,
    #[serde(rename = "body")]
    pub body: String,
    #[serde(rename = "cid")]
    pub cid: String,
    #[serde(rename = "created_time")]
    pub created_time: String,
    #[serde(rename = "detections")]
    pub detections: Vec<crate::models::MessagesPeriodDetection>,
    #[serde(rename = "hosts")]
    pub hosts: Vec<String>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "incidents")]
    pub incidents: Vec<crate::models::MessagesPeriodIncident>,
    #[serde(rename = "ip_addresses")]
    pub ip_addresses: Vec<String>,
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "last_modified_time")]
    pub last_modified_time: String,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "title")]
    pub title: String,
    #[serde(rename = "type")]
    pub r#type: String,
}

impl MessagesPeriodCase {
    pub fn new(
        aids: Vec<String>,
        assigner: crate::models::MessagesPeriodAuthor,
        attachments: Vec<crate::models::MessagesPeriodAttachment>,
        body: String,
        cid: String,
        created_time: String,
        detections: Vec<crate::models::MessagesPeriodDetection>,
        hosts: Vec<String>,
        id: String,
        incidents: Vec<crate::models::MessagesPeriodIncident>,
        ip_addresses: Vec<String>,
        key: String,
        last_modified_time: String,
        status: String,
        title: String,
        r#type: String,
    ) -> MessagesPeriodCase {
        MessagesPeriodCase {
            aids,
            assigner: Box::new(assigner),
            attachments,
            body,
            cid,
            created_time,
            detections,
            hosts,
            id,
            incidents,
            ip_addresses,
            key,
            last_modified_time,
            status,
            title,
            r#type,
        }
    }
}
