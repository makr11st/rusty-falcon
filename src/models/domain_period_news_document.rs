/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and examples, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation).     To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`.    Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: 2023-08-08T23:00:01Z
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct DomainPeriodNewsDocument {
    /// legacy field, not used
    #[serde(rename = "active", skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    /// Actors mentioned, related or referenced in the news/report
    #[serde(rename = "actors")]
    pub actors: Vec<crate::models::DomainPeriodSimpleActor>,
    /// News attachment, containing either pdf url or feeds zip and/or gzip archive
    #[serde(rename = "attachments", skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<crate::models::DomainPeriodFile>>,
    /// Date of the news document creation, unix timestampt
    #[serde(rename = "created_date")]
    pub created_date: i64,
    /// Full report description, extracted from the document
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// internal property used for permissions check of access, not returned or explicitly filterable
    #[serde(rename = "entitlements", skip_serializing_if = "Option::is_none")]
    pub entitlements: Option<Vec<crate::models::DomainPeriodEntity>>,
    /// Integer ID of the News document
    #[serde(rename = "id")]
    pub id: i64,
    #[serde(rename = "image", skip_serializing_if = "Option::is_none")]
    pub image: Option<Box<crate::models::DomainPeriodImage>>,
    /// Date of the news document last modification, unix timestampt
    #[serde(rename = "last_modified_date")]
    pub last_modified_date: i64,
    /// News mentioned motivation or motivation of related actors and malware families
    #[serde(rename = "motivations")]
    pub motivations: Vec<crate::models::DomainPeriodEntity>,
    /// News title
    #[serde(rename = "name")]
    pub name: String,
    /// internal field, not used
    #[serde(rename = "notify_users", skip_serializing_if = "Option::is_none")]
    pub notify_users: Option<bool>,
    /// Rich text description with markup
    #[serde(
        rename = "rich_text_description",
        skip_serializing_if = "Option::is_none"
    )]
    pub rich_text_description: Option<String>,
    /// Short description of the report content
    #[serde(rename = "short_description", skip_serializing_if = "Option::is_none")]
    pub short_description: Option<String>,
    /// News title in a url friendly way, which is title in lowercase and special characters including space replaced with dash
    #[serde(rename = "slug")]
    pub slug: String,
    #[serde(rename = "sub_type", skip_serializing_if = "Option::is_none")]
    pub sub_type: Option<Box<crate::models::DomainPeriodEntity>>,
    /// News tags, which contains MITRE, Vulnerability community identifiers, capabilities, malware family name, customer target, activity cluster, notable event, geopolitical issue
    #[serde(rename = "tags")]
    pub tags: Vec<crate::models::DomainPeriodEntity>,
    /// News mentioned target countries or related actor's target countries
    #[serde(rename = "target_countries")]
    pub target_countries: Vec<crate::models::DomainPeriodEntity>,
    /// News mentioned target industries or related actor's target industries
    #[serde(rename = "target_industries")]
    pub target_industries: Vec<crate::models::DomainPeriodEntity>,
    #[serde(rename = "thumbnail")]
    pub thumbnail: Box<crate::models::DomainPeriodImage>,
    #[serde(rename = "topic", skip_serializing_if = "Option::is_none")]
    pub topic: Option<Box<crate::models::DomainPeriodEntity>>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub r#type: Option<Box<crate::models::DomainPeriodEntity>>,
    /// URL of the news document where it can be accessed in the Falcon Portal
    #[serde(rename = "url", skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl DomainPeriodNewsDocument {
    pub fn new(
        actors: Vec<crate::models::DomainPeriodSimpleActor>,
        created_date: i64,
        id: i64,
        last_modified_date: i64,
        motivations: Vec<crate::models::DomainPeriodEntity>,
        name: String,
        slug: String,
        tags: Vec<crate::models::DomainPeriodEntity>,
        target_countries: Vec<crate::models::DomainPeriodEntity>,
        target_industries: Vec<crate::models::DomainPeriodEntity>,
        thumbnail: crate::models::DomainPeriodImage,
    ) -> DomainPeriodNewsDocument {
        DomainPeriodNewsDocument {
            active: None,
            actors,
            attachments: None,
            created_date,
            description: None,
            entitlements: None,
            id,
            image: None,
            last_modified_date,
            motivations,
            name,
            notify_users: None,
            rich_text_description: None,
            short_description: None,
            slug,
            sub_type: None,
            tags,
            target_countries,
            target_industries,
            thumbnail: Box::new(thumbnail),
            topic: None,
            r#type: None,
            url: None,
        }
    }
}
