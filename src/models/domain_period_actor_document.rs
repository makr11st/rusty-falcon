/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and examples, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation).     To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`.    Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: 2023-08-23T23:00:01Z
 *
 * Generated by: https://openapi-generator.tech
 */

/// DomainPeriodActorDocument : JSON definition of an Actor, also known as Adversary

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct DomainPeriodActorDocument {
    /// Boolean field marking if actor is active
    #[serde(rename = "active")]
    pub active: bool,
    /// Actor type, one of: targeted, ecrime
    #[serde(rename = "actor_type", skip_serializing_if = "Option::is_none")]
    pub actor_type: Option<String>,
    /// actor's capabilities, some examples: RAT,Ransomware,Spearphishing,Downloader,Backdoor,InformationStealer,exploit,CredentialHarvesting,dropper,DenialOfService,Loader,Phishing
    #[serde(rename = "capabilities")]
    pub capabilities: Vec<crate::models::DomainPeriodEntity>,
    #[serde(rename = "capability", skip_serializing_if = "Option::is_none")]
    pub capability: Option<Box<crate::models::DomainPeriodEntity>>,
    /// Actor's document creation date when it was added to the Falcon portal in unix timestamp format
    #[serde(rename = "created_date")]
    pub created_date: i64,
    /// Actor's text description, partially containing structured data from other fields
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "ecrime_kill_chain", skip_serializing_if = "Option::is_none")]
    pub ecrime_kill_chain: Option<Box<crate::models::DomainPeriodECrimeKillChain>>,
    /// Field used to filter user's access to actor documents
    #[serde(rename = "entitlements", skip_serializing_if = "Option::is_none")]
    pub entitlements: Option<Vec<crate::models::DomainPeriodEntity>>,
    /// Actor's first activity observed date in unix timestamp format
    #[serde(rename = "first_activity_date")]
    pub first_activity_date: i64,
    #[serde(rename = "group", skip_serializing_if = "Option::is_none")]
    pub group: Option<Box<crate::models::DomainPeriodEntity>>,
    /// Numerical ID for the Actor
    #[serde(rename = "id")]
    pub id: i64,
    #[serde(rename = "image", skip_serializing_if = "Option::is_none")]
    pub image: Option<Box<crate::models::DomainPeriodImage>>,
    #[serde(rename = "kill_chain", skip_serializing_if = "Option::is_none")]
    pub kill_chain: Option<Box<crate::models::DomainPeriodKillChain>>,
    /// Alternative names and community identifiers of an actor
    #[serde(rename = "known_as")]
    pub known_as: String,
    /// Actor's last (most recent) activity observed date in unix timestamp format
    #[serde(rename = "last_activity_date")]
    pub last_activity_date: i64,
    /// Actor's document last modified date in unix timestamp format
    #[serde(rename = "last_modified_date")]
    pub last_modified_date: i64,
    /// Actor's activity motivation, one of: State-Sponsored, Criminal, Hacktivism
    #[serde(rename = "motivations")]
    pub motivations: Vec<crate::models::DomainPeriodEntity>,
    /// Actor's name, composed of 2 words
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// internal field
    #[serde(rename = "notify_users")]
    pub notify_users: bool,
    /// Actor's activity objectives, one of: IntelligenceGathering, FinancialGain, IntellectualPropertyTheft, defacement, Destruction, DenialOfService
    #[serde(rename = "objectives")]
    pub objectives: Vec<crate::models::DomainPeriodEntity>,
    /// represents origin of actor's activity and/or members, some examples: China,Russian Federation,Eastern Europe,Iran,East Asia, South Asia
    #[serde(rename = "origins")]
    pub origins: Vec<crate::models::DomainPeriodEntity>,
    /// Recent CrowdStrike's finished intelligence alerting date in unix timestamp format
    #[serde(rename = "recent_alerting", skip_serializing_if = "Option::is_none")]
    pub recent_alerting: Option<i64>,
    #[serde(rename = "region", skip_serializing_if = "Option::is_none")]
    pub region: Option<Box<crate::models::DomainPeriodEntity>>,
    /// Rich text version of the description field
    #[serde(
        rename = "rich_text_description",
        skip_serializing_if = "Option::is_none"
    )]
    pub rich_text_description: Option<String>,
    /// Short version of the description field
    #[serde(rename = "short_description")]
    pub short_description: String,
    /// Name in url friendly format, lowercased and spaces replaced with dash
    #[serde(rename = "slug", skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    /// Status of an actor, one of: Active, Inactive, Retired
    #[serde(rename = "status")]
    pub status: String,
    /// Target countries of actor's activity and attacks, slug value is a 2 characters code for the country value, some examples: United States,United Kingdom,Germany,India,Japan,France,Australia,Canada,China
    #[serde(rename = "target_countries")]
    pub target_countries: Vec<crate::models::DomainPeriodEntity>,
    /// Target economical industries of actor's activity and attacks. List of available values: Government, Financial Services, Technology, Telecommunications, Healthcare, Energy, Academic, Media, Aerospace, NGO, Manufacturing, Industrials and Engineering, Retail, Hospitality, Consulting and Professional Services, Opportunistic, Aviation, Defense, Transportation, Oil and Gas, Legal, Pharmaceutical, Logistics, Military, Automotive, Food and Beverage, Consumer Goods, Real Estate, Insurance, Agriculture, Chemicals, Utilities, Maritime, Extractive, Travel, Dissident, Cryptocurrency, Entertainment, National Government, Law Enforcement, Think Tanks, Local Government, Sports Organizations, Computer Gaming, Biomedical, Nonprofit, Financial Management & Hedge Funds, Political Parties, Architectural and Engineering, Emergency Services, Social Media, International Government, Nuclear, Research Entities, Vocational and Higher-Level Education, eCommerce
    #[serde(rename = "target_industries")]
    pub target_industries: Vec<crate::models::DomainPeriodEntity>,
    /// Target geographic regions of actor's activity and attacks. List of available values: North America, Western Europe, Southeast Asia, Middle East, Eastern Europe, South Asia, South America, Oceania, East Asia, Central Africa, Northern Europe, Southern Europe, North Africa, Southern Africa, Central America, Central Asia, East Africa, West Africa, Caribbean
    #[serde(rename = "target_regions")]
    pub target_regions: Vec<crate::models::DomainPeriodEntity>,
    #[serde(rename = "thumbnail", skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<Box<crate::models::DomainPeriodImage>>,
    /// URL at which actor profile can be accessed
    #[serde(rename = "url", skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl DomainPeriodActorDocument {
    /// JSON definition of an Actor, also known as Adversary
    pub fn new(
        active: bool,
        capabilities: Vec<crate::models::DomainPeriodEntity>,
        created_date: i64,
        first_activity_date: i64,
        id: i64,
        known_as: String,
        last_activity_date: i64,
        last_modified_date: i64,
        motivations: Vec<crate::models::DomainPeriodEntity>,
        notify_users: bool,
        objectives: Vec<crate::models::DomainPeriodEntity>,
        origins: Vec<crate::models::DomainPeriodEntity>,
        short_description: String,
        status: String,
        target_countries: Vec<crate::models::DomainPeriodEntity>,
        target_industries: Vec<crate::models::DomainPeriodEntity>,
        target_regions: Vec<crate::models::DomainPeriodEntity>,
    ) -> DomainPeriodActorDocument {
        DomainPeriodActorDocument {
            active,
            actor_type: None,
            capabilities,
            capability: None,
            created_date,
            description: None,
            ecrime_kill_chain: None,
            entitlements: None,
            first_activity_date,
            group: None,
            id,
            image: None,
            kill_chain: None,
            known_as,
            last_activity_date,
            last_modified_date,
            motivations,
            name: None,
            notify_users,
            objectives,
            origins,
            recent_alerting: None,
            region: None,
            rich_text_description: None,
            short_description,
            slug: None,
            status,
            target_countries,
            target_industries,
            target_regions,
            thumbnail: None,
            url: None,
        }
    }
}
