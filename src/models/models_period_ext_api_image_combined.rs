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
pub struct ModelsPeriodExtApiImageCombined {
    #[serde(rename = "base_os")]
    pub base_os: String,
    #[serde(rename = "cid")]
    pub cid: String,
    #[serde(rename = "containers")]
    pub containers: i64,
    #[serde(rename = "detections")]
    pub detections: i32,
    #[serde(rename = "first_seen")]
    pub first_seen: String,
    #[serde(rename = "highest_detection_severity")]
    pub highest_detection_severity: String,
    #[serde(rename = "highest_vulnerability_severity")]
    pub highest_vulnerability_severity: String,
    #[serde(rename = "image_digest")]
    pub image_digest: String,
    #[serde(rename = "image_id")]
    pub image_id: String,
    #[serde(rename = "last_seen")]
    pub last_seen: String,
    #[serde(rename = "layers_with_vulnerabilities")]
    pub layers_with_vulnerabilities: i32,
    #[serde(rename = "packages")]
    pub packages: i32,
    #[serde(rename = "registry")]
    pub registry: String,
    #[serde(rename = "report_url_by_id_and_digest")]
    pub report_url_by_id_and_digest: String,
    #[serde(rename = "report_url_by_repo_and_tag")]
    pub report_url_by_repo_and_tag: String,
    #[serde(rename = "repository")]
    pub repository: String,
    #[serde(rename = "tag")]
    pub tag: String,
    #[serde(rename = "vulnerabilities")]
    pub vulnerabilities: i32,
    #[serde(rename = "warning")]
    pub warning: i32,
}

impl ModelsPeriodExtApiImageCombined {
    pub fn new(
        base_os: String,
        cid: String,
        containers: i64,
        detections: i32,
        first_seen: String,
        highest_detection_severity: String,
        highest_vulnerability_severity: String,
        image_digest: String,
        image_id: String,
        last_seen: String,
        layers_with_vulnerabilities: i32,
        packages: i32,
        registry: String,
        report_url_by_id_and_digest: String,
        report_url_by_repo_and_tag: String,
        repository: String,
        tag: String,
        vulnerabilities: i32,
        warning: i32,
    ) -> ModelsPeriodExtApiImageCombined {
        ModelsPeriodExtApiImageCombined {
            base_os,
            cid,
            containers,
            detections,
            first_seen,
            highest_detection_severity,
            highest_vulnerability_severity,
            image_digest,
            image_id,
            last_seen,
            layers_with_vulnerabilities,
            packages,
            registry,
            report_url_by_id_and_digest,
            report_url_by_repo_and_tag,
            repository,
            tag,
            vulnerabilities,
            warning,
        }
    }
}
