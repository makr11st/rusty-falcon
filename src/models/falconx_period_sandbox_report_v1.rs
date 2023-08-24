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
pub struct FalconxPeriodSandboxReportV1 {
    #[serde(rename = "architecture", skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(rename = "certificates", skip_serializing_if = "Option::is_none")]
    pub certificates: Option<Vec<crate::models::FalconxPeriodCertificate>>,
    #[serde(
        rename = "certificates_validation_message",
        skip_serializing_if = "Option::is_none"
    )]
    pub certificates_validation_message: Option<String>,
    #[serde(rename = "classification", skip_serializing_if = "Option::is_none")]
    pub classification: Option<Vec<String>>,
    #[serde(
        rename = "classification_tags",
        skip_serializing_if = "Option::is_none"
    )]
    pub classification_tags: Option<Vec<String>>,
    #[serde(rename = "contacted_hosts", skip_serializing_if = "Option::is_none")]
    pub contacted_hosts: Option<Vec<crate::models::FalconxPeriodContactedHost>>,
    #[serde(
        rename = "dll_characteristics",
        skip_serializing_if = "Option::is_none"
    )]
    pub dll_characteristics: Option<Vec<String>>,
    #[serde(rename = "dns_requests", skip_serializing_if = "Option::is_none")]
    pub dns_requests: Option<Vec<crate::models::FalconxPeriodDnsRequest>>,
    #[serde(rename = "entrypoint", skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>,
    #[serde(
        rename = "entrypoint_preview_count",
        skip_serializing_if = "Option::is_none"
    )]
    pub entrypoint_preview_count: Option<i32>,
    #[serde(
        rename = "entrypoint_preview_instructions",
        skip_serializing_if = "Option::is_none"
    )]
    pub entrypoint_preview_instructions: Option<Vec<String>>,
    #[serde(rename = "entrypoint_section", skip_serializing_if = "Option::is_none")]
    pub entrypoint_section: Option<String>,
    #[serde(
        rename = "environment_description",
        skip_serializing_if = "Option::is_none"
    )]
    pub environment_description: Option<String>,
    #[serde(rename = "environment_id", skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<i32>,
    #[serde(rename = "error_message", skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(rename = "error_origin", skip_serializing_if = "Option::is_none")]
    pub error_origin: Option<String>,
    #[serde(rename = "error_type", skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    #[serde(rename = "exact_deep_hash", skip_serializing_if = "Option::is_none")]
    pub exact_deep_hash: Option<String>,
    #[serde(rename = "extracted_files", skip_serializing_if = "Option::is_none")]
    pub extracted_files: Option<Vec<crate::models::FalconxPeriodExtractedFile>>,
    #[serde(
        rename = "extracted_interesting_strings",
        skip_serializing_if = "Option::is_none"
    )]
    pub extracted_interesting_strings:
        Option<Vec<crate::models::FalconxPeriodExtractedInterestingString>>,
    #[serde(
        rename = "file_data_directories",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_data_directories: Option<Vec<crate::models::FalconxPeriodFileDataDirectory>>,
    #[serde(rename = "file_imports", skip_serializing_if = "Option::is_none")]
    pub file_imports: Option<Vec<crate::models::FalconxPeriodFileImport>>,
    #[serde(rename = "file_metadata", skip_serializing_if = "Option::is_none")]
    pub file_metadata: Option<Box<crate::models::FalconxPeriodFileMetadata>>,
    #[serde(rename = "file_resources", skip_serializing_if = "Option::is_none")]
    pub file_resources: Option<Vec<crate::models::FalconxPeriodFileResource>>,
    #[serde(rename = "file_sections", skip_serializing_if = "Option::is_none")]
    pub file_sections: Option<Vec<crate::models::FalconxPeriodFileSection>>,
    #[serde(rename = "file_size", skip_serializing_if = "Option::is_none")]
    pub file_size: Option<i32>,
    #[serde(rename = "file_type", skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
    #[serde(rename = "file_type_short", skip_serializing_if = "Option::is_none")]
    pub file_type_short: Option<Vec<String>>,
    #[serde(rename = "http_requests", skip_serializing_if = "Option::is_none")]
    pub http_requests: Option<Vec<crate::models::FalconxPeriodHttpRequest>>,
    #[serde(rename = "icon", skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(rename = "image_base", skip_serializing_if = "Option::is_none")]
    pub image_base: Option<String>,
    #[serde(
        rename = "image_file_characteristics",
        skip_serializing_if = "Option::is_none"
    )]
    pub image_file_characteristics: Option<Vec<String>>,
    #[serde(rename = "incidents", skip_serializing_if = "Option::is_none")]
    pub incidents: Option<Vec<crate::models::FalconxPeriodIncident>>,
    #[serde(
        rename = "intelligence_mitre_attacks",
        skip_serializing_if = "Option::is_none"
    )]
    pub intelligence_mitre_attacks: Option<Vec<crate::models::FalconxPeriodMitreAttack>>,
    #[serde(
        rename = "ioc_report_broad_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub ioc_report_broad_artifact_id: Option<String>,
    #[serde(
        rename = "ioc_report_strict_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub ioc_report_strict_artifact_id: Option<String>,
    #[serde(rename = "is_certificates_valid")]
    pub is_certificates_valid: bool,
    #[serde(rename = "language", skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(rename = "major_os_version", skip_serializing_if = "Option::is_none")]
    pub major_os_version: Option<i32>,
    #[serde(rename = "memory_dumps", skip_serializing_if = "Option::is_none")]
    pub memory_dumps: Option<Vec<crate::models::FalconxPeriodMemoryDumpData>>,
    #[serde(
        rename = "memory_dumps_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub memory_dumps_artifact_id: Option<String>,
    #[serde(rename = "memory_forensics", skip_serializing_if = "Option::is_none")]
    pub memory_forensics: Option<Vec<crate::models::FalconxPeriodMemoryForensic>>,
    #[serde(
        rename = "memory_strings_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub memory_strings_artifact_id: Option<String>,
    #[serde(rename = "minor_os_version", skip_serializing_if = "Option::is_none")]
    pub minor_os_version: Option<i32>,
    #[serde(rename = "mitre_attacks", skip_serializing_if = "Option::is_none")]
    pub mitre_attacks: Option<Vec<crate::models::FalconxPeriodMitreAttack>>,
    #[serde(rename = "network_settings", skip_serializing_if = "Option::is_none")]
    pub network_settings: Option<String>,
    #[serde(rename = "packer", skip_serializing_if = "Option::is_none")]
    pub packer: Option<String>,
    #[serde(
        rename = "pcap_report_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub pcap_report_artifact_id: Option<String>,
    #[serde(rename = "processes", skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<crate::models::FalconxPeriodProcess>>,
    #[serde(rename = "sample_flags", skip_serializing_if = "Option::is_none")]
    pub sample_flags: Option<Vec<String>>,
    #[serde(
        rename = "screenshots_artifact_ids",
        skip_serializing_if = "Option::is_none"
    )]
    pub screenshots_artifact_ids: Option<Vec<String>>,
    #[serde(rename = "sha256", skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(rename = "signatures", skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<crate::models::FalconxPeriodSignature>>,
    #[serde(rename = "submission_type", skip_serializing_if = "Option::is_none")]
    pub submission_type: Option<String>,
    #[serde(rename = "submit_name", skip_serializing_if = "Option::is_none")]
    pub submit_name: Option<String>,
    #[serde(rename = "submit_url", skip_serializing_if = "Option::is_none")]
    pub submit_url: Option<String>,
    #[serde(rename = "subsystem", skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
    #[serde(rename = "suricata_alerts", skip_serializing_if = "Option::is_none")]
    pub suricata_alerts: Option<Vec<crate::models::FalconxPeriodSuricataAlert>>,
    #[serde(rename = "target_url", skip_serializing_if = "Option::is_none")]
    pub target_url: Option<String>,
    #[serde(rename = "threat_score", skip_serializing_if = "Option::is_none")]
    pub threat_score: Option<i32>,
    #[serde(rename = "urls", skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<crate::models::FalconxPeriodUrlData>>,
    #[serde(rename = "verdict", skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    #[serde(rename = "version_info", skip_serializing_if = "Option::is_none")]
    pub version_info: Option<Vec<crate::models::FalconxPeriodVersionInfo>>,
    #[serde(rename = "visualization", skip_serializing_if = "Option::is_none")]
    pub visualization: Option<String>,
    #[serde(
        rename = "windows_version_bitness",
        skip_serializing_if = "Option::is_none"
    )]
    pub windows_version_bitness: Option<i32>,
    #[serde(
        rename = "windows_version_edition",
        skip_serializing_if = "Option::is_none"
    )]
    pub windows_version_edition: Option<String>,
    #[serde(
        rename = "windows_version_name",
        skip_serializing_if = "Option::is_none"
    )]
    pub windows_version_name: Option<String>,
    #[serde(
        rename = "windows_version_service_pack",
        skip_serializing_if = "Option::is_none"
    )]
    pub windows_version_service_pack: Option<String>,
    #[serde(
        rename = "windows_version_version",
        skip_serializing_if = "Option::is_none"
    )]
    pub windows_version_version: Option<String>,
}

impl FalconxPeriodSandboxReportV1 {
    pub fn new(is_certificates_valid: bool) -> FalconxPeriodSandboxReportV1 {
        FalconxPeriodSandboxReportV1 {
            architecture: None,
            certificates: None,
            certificates_validation_message: None,
            classification: None,
            classification_tags: None,
            contacted_hosts: None,
            dll_characteristics: None,
            dns_requests: None,
            entrypoint: None,
            entrypoint_preview_count: None,
            entrypoint_preview_instructions: None,
            entrypoint_section: None,
            environment_description: None,
            environment_id: None,
            error_message: None,
            error_origin: None,
            error_type: None,
            exact_deep_hash: None,
            extracted_files: None,
            extracted_interesting_strings: None,
            file_data_directories: None,
            file_imports: None,
            file_metadata: None,
            file_resources: None,
            file_sections: None,
            file_size: None,
            file_type: None,
            file_type_short: None,
            http_requests: None,
            icon: None,
            image_base: None,
            image_file_characteristics: None,
            incidents: None,
            intelligence_mitre_attacks: None,
            ioc_report_broad_artifact_id: None,
            ioc_report_strict_artifact_id: None,
            is_certificates_valid,
            language: None,
            major_os_version: None,
            memory_dumps: None,
            memory_dumps_artifact_id: None,
            memory_forensics: None,
            memory_strings_artifact_id: None,
            minor_os_version: None,
            mitre_attacks: None,
            network_settings: None,
            packer: None,
            pcap_report_artifact_id: None,
            processes: None,
            sample_flags: None,
            screenshots_artifact_ids: None,
            sha256: None,
            signatures: None,
            submission_type: None,
            submit_name: None,
            submit_url: None,
            subsystem: None,
            suricata_alerts: None,
            target_url: None,
            threat_score: None,
            urls: None,
            verdict: None,
            version_info: None,
            visualization: None,
            windows_version_bitness: None,
            windows_version_edition: None,
            windows_version_name: None,
            windows_version_service_pack: None,
            windows_version_version: None,
        }
    }
}
