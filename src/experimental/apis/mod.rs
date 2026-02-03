use std::{error, fmt};

#[derive(Debug, Clone)]
pub struct ResponseContent<T> {
    pub status: reqwest::StatusCode,
    pub content: String,
    pub entity: Option<T>,
}

#[derive(Debug)]
pub enum Error<T> {
    Reqwest(reqwest::Error),
    Serde(serde_json::Error),
    Io(std::io::Error),
    ResponseError(ResponseContent<T>),
}

impl<T> fmt::Display for Error<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (module, e) = match self {
            Error::Reqwest(e) => ("reqwest", e.to_string()),
            Error::Serde(e) => ("serde", e.to_string()),
            Error::Io(e) => ("IO", e.to_string()),
            Error::ResponseError(e) => ("response", format!("status code {}", e.status)),
        };
        write!(f, "error in {}: {}", module, e)
    }
}

impl<T: fmt::Debug> error::Error for Error<T> {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(match self {
            Error::Reqwest(e) => e,
            Error::Serde(e) => e,
            Error::Io(e) => e,
            Error::ResponseError(_) => return None,
        })
    }
}

impl<T> From<reqwest::Error> for Error<T> {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl<T> From<serde_json::Error> for Error<T> {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl<T> From<std::io::Error> for Error<T> {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub fn urlencode<T: AsRef<str>>(s: T) -> String {
    ::url::form_urlencoded::byte_serialize(s.as_ref().as_bytes()).collect()
}

pub fn parse_deep_object(prefix: &str, value: &serde_json::Value) -> Vec<(String, String)> {
    if let serde_json::Value::Object(object) = value {
        let mut params = vec![];

        for (key, value) in object {
            match value {
                serde_json::Value::Object(_) => params.append(&mut parse_deep_object(
                    &format!("{}[{}]", prefix, key),
                    value,
                )),
                serde_json::Value::Array(array) => {
                    for (i, value) in array.iter().enumerate() {
                        params.append(&mut parse_deep_object(
                            &format!("{}[{}][{}]", prefix, key, i),
                            value,
                        ));
                    }
                }
                serde_json::Value::String(s) => {
                    params.push((format!("{}[{}]", prefix, key), s.clone()))
                }
                _ => params.push((format!("{}[{}]", prefix, key), value.to_string())),
            }
        }

        return params;
    }

    unimplemented!("Only objects are supported with style=deepObject")
}

/// Internal use only
/// A content type supported by this client.
#[allow(dead_code)]
enum ContentType {
    Json,
    Text,
    Unsupported(String),
}

impl From<&str> for ContentType {
    fn from(content_type: &str) -> Self {
        if content_type.starts_with("application") && content_type.contains("json") {
            return Self::Json;
        } else if content_type.starts_with("text/plain") {
            return Self::Text;
        } else {
            return Self::Unsupported(content_type.to_string());
        }
    }
}

pub mod admission_control_policies_api;
pub mod alerts_api;
pub mod api_integrations_api;
pub mod aspm_api;
pub mod cao_hunting_api;
pub mod case_files_api;
pub mod case_management_api;
pub mod cases_api;
pub mod certificate_based_exclusions_api;
pub mod cloud_aws_registration_api;
pub mod cloud_azure_registration_api;
pub mod cloud_connect_aws_api;
pub mod cloud_google_cloud_registration_api;
pub mod cloud_oci_registration_api;
pub mod cloud_policies_api;
pub mod cloud_security_api;
pub mod cloud_security_assets_api;
pub mod cloud_security_compliance_api;
pub mod cloud_security_detections_api;
pub mod cloud_snapshots_api;
pub mod configuration_assessment_api;
pub mod configuration_assessment_evaluation_logic_api;
pub mod container_alerts_api;
pub mod container_detections_api;
pub mod container_image_compliance_api;
pub mod container_images_api;
pub mod container_packages_api;
pub mod container_vulnerabilities_api;
pub mod content_update_policies_api;
pub mod correlation_rules_admin_api;
pub mod correlation_rules_api;
pub mod cspg_iacapi_api;
pub mod cspm_registration_api;
pub mod custom_ioa_api;
pub mod custom_storage_api;
pub mod d4c_registration_api;
pub mod data_protection_configuration_api;
pub mod default_api;
pub mod delivery_settings_api;
pub mod deployments_api;
pub mod detects_api;
pub mod device_content_api;
pub mod device_control_policies_api;
pub mod device_control_with_bluetooth_api;
pub mod discover_api;
pub mod discover_iot_api;
pub mod downloads_api_api;
pub mod drift_indicators_api;
pub mod event_schema_api;
pub mod event_streams_api;
pub mod execution_api;
pub mod exposure_management_api;
pub mod falcon_complete_dashboard_api;
pub mod falcon_container_api;
pub mod falcon_container_cli_api;
pub mod falcon_container_image_api;
pub mod falconx_sandbox_api;
pub mod field_schema_api;
pub mod filevantage_api;
pub mod firewall_management_api;
pub mod firewall_policies_api;
pub mod foundry_logscale_api;
pub mod host_group_api;
pub mod host_migration_api;
pub mod hosts_api;
pub mod identity_entities_api;
pub mod identity_protection_api;
pub mod image_assessment_policies_api;
pub mod incidents_api;
pub mod installation_tokens_api;
pub mod installation_tokens_settings_api;
pub mod intel_api;
pub mod intelligence_feeds_api;
pub mod intelligence_indicator_graph_api;
pub mod ioa_exclusions_api;
pub mod ioc_api;
pub mod iocs_api;
pub mod it_automation_api;
pub mod kubernetes_container_compliance_api;
pub mod kubernetes_protection_api;
pub mod lookup_files_api;
pub mod malquery_api;
pub mod message_center_api;
pub mod ml_exclusions_api;
pub mod mobile_enrollment_api;
pub mod mssp_api;
pub mod ngsiem_api;
pub mod oauth2_api;
pub mod ods_api;
pub mod prevention_policies_api;
pub mod quarantine_api;
pub mod quick_scan_api;
pub mod quick_scan_pro_api;
pub mod real_time_response_admin_api;
pub mod real_time_response_api;
pub mod real_time_response_audit_api;
pub mod recon_api;
pub mod release_notes_api;
pub mod releases_api;
pub mod report_executions_api;
pub mod response_policies_api;
pub mod runtime_detections_api;
pub mod saas_security_api;
pub mod sample_uploads_api;
pub mod scheduled_reports_api;
pub mod sensor_download_api;
pub mod sensor_update_policies_api;
pub mod sensor_usage_api_api;
pub mod sensor_visibility_exclusions_api;
pub mod serverless_vulnerabilities_api;
pub mod spotlight_evaluation_logic_api;
pub mod spotlight_vulnerabilities_api;
pub mod tailored_intelligence_api;
pub mod threatgraph_api;
pub mod unidentified_containers_api;
pub mod user_management_api;
pub mod workflows_api;
pub mod zero_trust_assessment_api;

pub mod configuration;

use std::sync::Arc;

pub trait Api {
    fn aspm_api(&self) -> &dyn aspm_api::AspmApi;
    fn admission_control_policies_api(
        &self,
    ) -> &dyn admission_control_policies_api::AdmissionControlPoliciesApi;
    fn alerts_api(&self) -> &dyn alerts_api::AlertsApi;
    fn api_integrations_api(&self) -> &dyn api_integrations_api::ApiIntegrationsApi;
    fn cao_hunting_api(&self) -> &dyn cao_hunting_api::CaoHuntingApi;
    fn case_files_api(&self) -> &dyn case_files_api::CaseFilesApi;
    fn case_management_api(&self) -> &dyn case_management_api::CaseManagementApi;
    fn cases_api(&self) -> &dyn cases_api::CasesApi;
    fn certificate_based_exclusions_api(
        &self,
    ) -> &dyn certificate_based_exclusions_api::CertificateBasedExclusionsApi;
    fn cloud_aws_registration_api(
        &self,
    ) -> &dyn cloud_aws_registration_api::CloudAwsRegistrationApi;
    fn cloud_azure_registration_api(
        &self,
    ) -> &dyn cloud_azure_registration_api::CloudAzureRegistrationApi;
    fn cloud_connect_aws_api(&self) -> &dyn cloud_connect_aws_api::CloudConnectAwsApi;
    fn cloud_google_cloud_registration_api(
        &self,
    ) -> &dyn cloud_google_cloud_registration_api::CloudGoogleCloudRegistrationApi;
    fn cloud_oci_registration_api(
        &self,
    ) -> &dyn cloud_oci_registration_api::CloudOciRegistrationApi;
    fn cloud_policies_api(&self) -> &dyn cloud_policies_api::CloudPoliciesApi;
    fn cloud_security_api(&self) -> &dyn cloud_security_api::CloudSecurityApi;
    fn cloud_security_assets_api(&self) -> &dyn cloud_security_assets_api::CloudSecurityAssetsApi;
    fn cloud_security_compliance_api(
        &self,
    ) -> &dyn cloud_security_compliance_api::CloudSecurityComplianceApi;
    fn cloud_security_detections_api(
        &self,
    ) -> &dyn cloud_security_detections_api::CloudSecurityDetectionsApi;
    fn cloud_snapshots_api(&self) -> &dyn cloud_snapshots_api::CloudSnapshotsApi;
    fn configuration_assessment_api(
        &self,
    ) -> &dyn configuration_assessment_api::ConfigurationAssessmentApi;
    fn configuration_assessment_evaluation_logic_api(
        &self,
    ) -> &dyn configuration_assessment_evaluation_logic_api::ConfigurationAssessmentEvaluationLogicApi;
    fn container_alerts_api(&self) -> &dyn container_alerts_api::ContainerAlertsApi;
    fn container_detections_api(&self) -> &dyn container_detections_api::ContainerDetectionsApi;
    fn container_image_compliance_api(
        &self,
    ) -> &dyn container_image_compliance_api::ContainerImageComplianceApi;
    fn container_images_api(&self) -> &dyn container_images_api::ContainerImagesApi;
    fn container_packages_api(&self) -> &dyn container_packages_api::ContainerPackagesApi;
    fn container_vulnerabilities_api(
        &self,
    ) -> &dyn container_vulnerabilities_api::ContainerVulnerabilitiesApi;
    fn content_update_policies_api(
        &self,
    ) -> &dyn content_update_policies_api::ContentUpdatePoliciesApi;
    fn correlation_rules_api(&self) -> &dyn correlation_rules_api::CorrelationRulesApi;
    fn correlation_rules_admin_api(
        &self,
    ) -> &dyn correlation_rules_admin_api::CorrelationRulesAdminApi;
    fn cspg_iacapi_api(&self) -> &dyn cspg_iacapi_api::CspgIacapiApi;
    fn cspm_registration_api(&self) -> &dyn cspm_registration_api::CspmRegistrationApi;
    fn custom_ioa_api(&self) -> &dyn custom_ioa_api::CustomIoaApi;
    fn custom_storage_api(&self) -> &dyn custom_storage_api::CustomStorageApi;
    fn d4c_registration_api(&self) -> &dyn d4c_registration_api::D4cRegistrationApi;
    fn data_protection_configuration_api(
        &self,
    ) -> &dyn data_protection_configuration_api::DataProtectionConfigurationApi;
    fn default_api(&self) -> &dyn default_api::DefaultApi;
    fn delivery_settings_api(&self) -> &dyn delivery_settings_api::DeliverySettingsApi;
    fn deployments_api(&self) -> &dyn deployments_api::DeploymentsApi;
    fn detects_api(&self) -> &dyn detects_api::DetectsApi;
    fn device_content_api(&self) -> &dyn device_content_api::DeviceContentApi;
    fn device_control_policies_api(
        &self,
    ) -> &dyn device_control_policies_api::DeviceControlPoliciesApi;
    fn device_control_with_bluetooth_api(
        &self,
    ) -> &dyn device_control_with_bluetooth_api::DeviceControlWithBluetoothApi;
    fn discover_api(&self) -> &dyn discover_api::DiscoverApi;
    fn discover_iot_api(&self) -> &dyn discover_iot_api::DiscoverIotApi;
    fn downloads_api_api(&self) -> &dyn downloads_api_api::DownloadsApiApi;
    fn drift_indicators_api(&self) -> &dyn drift_indicators_api::DriftIndicatorsApi;
    fn event_schema_api(&self) -> &dyn event_schema_api::EventSchemaApi;
    fn event_streams_api(&self) -> &dyn event_streams_api::EventStreamsApi;
    fn execution_api(&self) -> &dyn execution_api::ExecutionApi;
    fn exposure_management_api(&self) -> &dyn exposure_management_api::ExposureManagementApi;
    fn falcon_complete_dashboard_api(
        &self,
    ) -> &dyn falcon_complete_dashboard_api::FalconCompleteDashboardApi;
    fn falcon_container_api(&self) -> &dyn falcon_container_api::FalconContainerApi;
    fn falcon_container_cli_api(&self) -> &dyn falcon_container_cli_api::FalconContainerCliApi;
    fn falcon_container_image_api(
        &self,
    ) -> &dyn falcon_container_image_api::FalconContainerImageApi;
    fn falconx_sandbox_api(&self) -> &dyn falconx_sandbox_api::FalconxSandboxApi;
    fn field_schema_api(&self) -> &dyn field_schema_api::FieldSchemaApi;
    fn filevantage_api(&self) -> &dyn filevantage_api::FilevantageApi;
    fn firewall_management_api(&self) -> &dyn firewall_management_api::FirewallManagementApi;
    fn firewall_policies_api(&self) -> &dyn firewall_policies_api::FirewallPoliciesApi;
    fn foundry_logscale_api(&self) -> &dyn foundry_logscale_api::FoundryLogscaleApi;
    fn host_group_api(&self) -> &dyn host_group_api::HostGroupApi;
    fn host_migration_api(&self) -> &dyn host_migration_api::HostMigrationApi;
    fn hosts_api(&self) -> &dyn hosts_api::HostsApi;
    fn identity_entities_api(&self) -> &dyn identity_entities_api::IdentityEntitiesApi;
    fn identity_protection_api(&self) -> &dyn identity_protection_api::IdentityProtectionApi;
    fn image_assessment_policies_api(
        &self,
    ) -> &dyn image_assessment_policies_api::ImageAssessmentPoliciesApi;
    fn incidents_api(&self) -> &dyn incidents_api::IncidentsApi;
    fn installation_tokens_api(&self) -> &dyn installation_tokens_api::InstallationTokensApi;
    fn installation_tokens_settings_api(
        &self,
    ) -> &dyn installation_tokens_settings_api::InstallationTokensSettingsApi;
    fn intel_api(&self) -> &dyn intel_api::IntelApi;
    fn intelligence_feeds_api(&self) -> &dyn intelligence_feeds_api::IntelligenceFeedsApi;
    fn intelligence_indicator_graph_api(
        &self,
    ) -> &dyn intelligence_indicator_graph_api::IntelligenceIndicatorGraphApi;
    fn ioa_exclusions_api(&self) -> &dyn ioa_exclusions_api::IoaExclusionsApi;
    fn ioc_api(&self) -> &dyn ioc_api::IocApi;
    fn iocs_api(&self) -> &dyn iocs_api::IocsApi;
    fn it_automation_api(&self) -> &dyn it_automation_api::ItAutomationApi;
    fn kubernetes_container_compliance_api(
        &self,
    ) -> &dyn kubernetes_container_compliance_api::KubernetesContainerComplianceApi;
    fn kubernetes_protection_api(&self) -> &dyn kubernetes_protection_api::KubernetesProtectionApi;
    fn lookup_files_api(&self) -> &dyn lookup_files_api::LookupFilesApi;
    fn malquery_api(&self) -> &dyn malquery_api::MalqueryApi;
    fn message_center_api(&self) -> &dyn message_center_api::MessageCenterApi;
    fn ml_exclusions_api(&self) -> &dyn ml_exclusions_api::MlExclusionsApi;
    fn mobile_enrollment_api(&self) -> &dyn mobile_enrollment_api::MobileEnrollmentApi;
    fn mssp_api(&self) -> &dyn mssp_api::MsspApi;
    fn ngsiem_api(&self) -> &dyn ngsiem_api::NgsiemApi;
    fn oauth2_api(&self) -> &dyn oauth2_api::Oauth2Api;
    fn ods_api(&self) -> &dyn ods_api::OdsApi;
    fn prevention_policies_api(&self) -> &dyn prevention_policies_api::PreventionPoliciesApi;
    fn quarantine_api(&self) -> &dyn quarantine_api::QuarantineApi;
    fn quick_scan_api(&self) -> &dyn quick_scan_api::QuickScanApi;
    fn quick_scan_pro_api(&self) -> &dyn quick_scan_pro_api::QuickScanProApi;
    fn real_time_response_api(&self) -> &dyn real_time_response_api::RealTimeResponseApi;
    fn real_time_response_admin_api(
        &self,
    ) -> &dyn real_time_response_admin_api::RealTimeResponseAdminApi;
    fn real_time_response_audit_api(
        &self,
    ) -> &dyn real_time_response_audit_api::RealTimeResponseAuditApi;
    fn recon_api(&self) -> &dyn recon_api::ReconApi;
    fn release_notes_api(&self) -> &dyn release_notes_api::ReleaseNotesApi;
    fn releases_api(&self) -> &dyn releases_api::ReleasesApi;
    fn report_executions_api(&self) -> &dyn report_executions_api::ReportExecutionsApi;
    fn response_policies_api(&self) -> &dyn response_policies_api::ResponsePoliciesApi;
    fn runtime_detections_api(&self) -> &dyn runtime_detections_api::RuntimeDetectionsApi;
    fn saas_security_api(&self) -> &dyn saas_security_api::SaasSecurityApi;
    fn sample_uploads_api(&self) -> &dyn sample_uploads_api::SampleUploadsApi;
    fn scheduled_reports_api(&self) -> &dyn scheduled_reports_api::ScheduledReportsApi;
    fn sensor_download_api(&self) -> &dyn sensor_download_api::SensorDownloadApi;
    fn sensor_update_policies_api(
        &self,
    ) -> &dyn sensor_update_policies_api::SensorUpdatePoliciesApi;
    fn sensor_usage_api_api(&self) -> &dyn sensor_usage_api_api::SensorUsageApiApi;
    fn sensor_visibility_exclusions_api(
        &self,
    ) -> &dyn sensor_visibility_exclusions_api::SensorVisibilityExclusionsApi;
    fn serverless_vulnerabilities_api(
        &self,
    ) -> &dyn serverless_vulnerabilities_api::ServerlessVulnerabilitiesApi;
    fn spotlight_evaluation_logic_api(
        &self,
    ) -> &dyn spotlight_evaluation_logic_api::SpotlightEvaluationLogicApi;
    fn spotlight_vulnerabilities_api(
        &self,
    ) -> &dyn spotlight_vulnerabilities_api::SpotlightVulnerabilitiesApi;
    fn tailored_intelligence_api(&self) -> &dyn tailored_intelligence_api::TailoredIntelligenceApi;
    fn threatgraph_api(&self) -> &dyn threatgraph_api::ThreatgraphApi;
    fn unidentified_containers_api(
        &self,
    ) -> &dyn unidentified_containers_api::UnidentifiedContainersApi;
    fn user_management_api(&self) -> &dyn user_management_api::UserManagementApi;
    fn workflows_api(&self) -> &dyn workflows_api::WorkflowsApi;
    fn zero_trust_assessment_api(&self) -> &dyn zero_trust_assessment_api::ZeroTrustAssessmentApi;
}

pub struct ApiClient {
    aspm_api: Box<dyn aspm_api::AspmApi>,
    admission_control_policies_api: Box<dyn admission_control_policies_api::AdmissionControlPoliciesApi>,
    alerts_api: Box<dyn alerts_api::AlertsApi>,
    api_integrations_api: Box<dyn api_integrations_api::ApiIntegrationsApi>,
    cao_hunting_api: Box<dyn cao_hunting_api::CaoHuntingApi>,
    case_files_api: Box<dyn case_files_api::CaseFilesApi>,
    case_management_api: Box<dyn case_management_api::CaseManagementApi>,
    cases_api: Box<dyn cases_api::CasesApi>,
    certificate_based_exclusions_api: Box<dyn certificate_based_exclusions_api::CertificateBasedExclusionsApi>,
    cloud_aws_registration_api: Box<dyn cloud_aws_registration_api::CloudAwsRegistrationApi>,
    cloud_azure_registration_api: Box<dyn cloud_azure_registration_api::CloudAzureRegistrationApi>,
    cloud_connect_aws_api: Box<dyn cloud_connect_aws_api::CloudConnectAwsApi>,
    cloud_google_cloud_registration_api: Box<dyn cloud_google_cloud_registration_api::CloudGoogleCloudRegistrationApi>,
    cloud_oci_registration_api: Box<dyn cloud_oci_registration_api::CloudOciRegistrationApi>,
    cloud_policies_api: Box<dyn cloud_policies_api::CloudPoliciesApi>,
    cloud_security_api: Box<dyn cloud_security_api::CloudSecurityApi>,
    cloud_security_assets_api: Box<dyn cloud_security_assets_api::CloudSecurityAssetsApi>,
    cloud_security_compliance_api: Box<dyn cloud_security_compliance_api::CloudSecurityComplianceApi>,
    cloud_security_detections_api: Box<dyn cloud_security_detections_api::CloudSecurityDetectionsApi>,
    cloud_snapshots_api: Box<dyn cloud_snapshots_api::CloudSnapshotsApi>,
    configuration_assessment_api: Box<dyn configuration_assessment_api::ConfigurationAssessmentApi>,
    configuration_assessment_evaluation_logic_api: Box<dyn configuration_assessment_evaluation_logic_api::ConfigurationAssessmentEvaluationLogicApi>,
    container_alerts_api: Box<dyn container_alerts_api::ContainerAlertsApi>,
    container_detections_api: Box<dyn container_detections_api::ContainerDetectionsApi>,
    container_image_compliance_api: Box<dyn container_image_compliance_api::ContainerImageComplianceApi>,
    container_images_api: Box<dyn container_images_api::ContainerImagesApi>,
    container_packages_api: Box<dyn container_packages_api::ContainerPackagesApi>,
    container_vulnerabilities_api: Box<dyn container_vulnerabilities_api::ContainerVulnerabilitiesApi>,
    content_update_policies_api: Box<dyn content_update_policies_api::ContentUpdatePoliciesApi>,
    correlation_rules_api: Box<dyn correlation_rules_api::CorrelationRulesApi>,
    correlation_rules_admin_api: Box<dyn correlation_rules_admin_api::CorrelationRulesAdminApi>,
    cspg_iacapi_api: Box<dyn cspg_iacapi_api::CspgIacapiApi>,
    cspm_registration_api: Box<dyn cspm_registration_api::CspmRegistrationApi>,
    custom_ioa_api: Box<dyn custom_ioa_api::CustomIoaApi>,
    custom_storage_api: Box<dyn custom_storage_api::CustomStorageApi>,
    d4c_registration_api: Box<dyn d4c_registration_api::D4cRegistrationApi>,
    data_protection_configuration_api: Box<dyn data_protection_configuration_api::DataProtectionConfigurationApi>,
    default_api: Box<dyn default_api::DefaultApi>,
    delivery_settings_api: Box<dyn delivery_settings_api::DeliverySettingsApi>,
    deployments_api: Box<dyn deployments_api::DeploymentsApi>,
    detects_api: Box<dyn detects_api::DetectsApi>,
    device_content_api: Box<dyn device_content_api::DeviceContentApi>,
    device_control_policies_api: Box<dyn device_control_policies_api::DeviceControlPoliciesApi>,
    device_control_with_bluetooth_api: Box<dyn device_control_with_bluetooth_api::DeviceControlWithBluetoothApi>,
    discover_api: Box<dyn discover_api::DiscoverApi>,
    discover_iot_api: Box<dyn discover_iot_api::DiscoverIotApi>,
    downloads_api_api: Box<dyn downloads_api_api::DownloadsApiApi>,
    drift_indicators_api: Box<dyn drift_indicators_api::DriftIndicatorsApi>,
    event_schema_api: Box<dyn event_schema_api::EventSchemaApi>,
    event_streams_api: Box<dyn event_streams_api::EventStreamsApi>,
    execution_api: Box<dyn execution_api::ExecutionApi>,
    exposure_management_api: Box<dyn exposure_management_api::ExposureManagementApi>,
    falcon_complete_dashboard_api: Box<dyn falcon_complete_dashboard_api::FalconCompleteDashboardApi>,
    falcon_container_api: Box<dyn falcon_container_api::FalconContainerApi>,
    falcon_container_cli_api: Box<dyn falcon_container_cli_api::FalconContainerCliApi>,
    falcon_container_image_api: Box<dyn falcon_container_image_api::FalconContainerImageApi>,
    falconx_sandbox_api: Box<dyn falconx_sandbox_api::FalconxSandboxApi>,
    field_schema_api: Box<dyn field_schema_api::FieldSchemaApi>,
    filevantage_api: Box<dyn filevantage_api::FilevantageApi>,
    firewall_management_api: Box<dyn firewall_management_api::FirewallManagementApi>,
    firewall_policies_api: Box<dyn firewall_policies_api::FirewallPoliciesApi>,
    foundry_logscale_api: Box<dyn foundry_logscale_api::FoundryLogscaleApi>,
    host_group_api: Box<dyn host_group_api::HostGroupApi>,
    host_migration_api: Box<dyn host_migration_api::HostMigrationApi>,
    hosts_api: Box<dyn hosts_api::HostsApi>,
    identity_entities_api: Box<dyn identity_entities_api::IdentityEntitiesApi>,
    identity_protection_api: Box<dyn identity_protection_api::IdentityProtectionApi>,
    image_assessment_policies_api: Box<dyn image_assessment_policies_api::ImageAssessmentPoliciesApi>,
    incidents_api: Box<dyn incidents_api::IncidentsApi>,
    installation_tokens_api: Box<dyn installation_tokens_api::InstallationTokensApi>,
    installation_tokens_settings_api: Box<dyn installation_tokens_settings_api::InstallationTokensSettingsApi>,
    intel_api: Box<dyn intel_api::IntelApi>,
    intelligence_feeds_api: Box<dyn intelligence_feeds_api::IntelligenceFeedsApi>,
    intelligence_indicator_graph_api: Box<dyn intelligence_indicator_graph_api::IntelligenceIndicatorGraphApi>,
    ioa_exclusions_api: Box<dyn ioa_exclusions_api::IoaExclusionsApi>,
    ioc_api: Box<dyn ioc_api::IocApi>,
    iocs_api: Box<dyn iocs_api::IocsApi>,
    it_automation_api: Box<dyn it_automation_api::ItAutomationApi>,
    kubernetes_container_compliance_api: Box<dyn kubernetes_container_compliance_api::KubernetesContainerComplianceApi>,
    kubernetes_protection_api: Box<dyn kubernetes_protection_api::KubernetesProtectionApi>,
    lookup_files_api: Box<dyn lookup_files_api::LookupFilesApi>,
    malquery_api: Box<dyn malquery_api::MalqueryApi>,
    message_center_api: Box<dyn message_center_api::MessageCenterApi>,
    ml_exclusions_api: Box<dyn ml_exclusions_api::MlExclusionsApi>,
    mobile_enrollment_api: Box<dyn mobile_enrollment_api::MobileEnrollmentApi>,
    mssp_api: Box<dyn mssp_api::MsspApi>,
    ngsiem_api: Box<dyn ngsiem_api::NgsiemApi>,
    oauth2_api: Box<dyn oauth2_api::Oauth2Api>,
    ods_api: Box<dyn ods_api::OdsApi>,
    prevention_policies_api: Box<dyn prevention_policies_api::PreventionPoliciesApi>,
    quarantine_api: Box<dyn quarantine_api::QuarantineApi>,
    quick_scan_api: Box<dyn quick_scan_api::QuickScanApi>,
    quick_scan_pro_api: Box<dyn quick_scan_pro_api::QuickScanProApi>,
    real_time_response_api: Box<dyn real_time_response_api::RealTimeResponseApi>,
    real_time_response_admin_api: Box<dyn real_time_response_admin_api::RealTimeResponseAdminApi>,
    real_time_response_audit_api: Box<dyn real_time_response_audit_api::RealTimeResponseAuditApi>,
    recon_api: Box<dyn recon_api::ReconApi>,
    release_notes_api: Box<dyn release_notes_api::ReleaseNotesApi>,
    releases_api: Box<dyn releases_api::ReleasesApi>,
    report_executions_api: Box<dyn report_executions_api::ReportExecutionsApi>,
    response_policies_api: Box<dyn response_policies_api::ResponsePoliciesApi>,
    runtime_detections_api: Box<dyn runtime_detections_api::RuntimeDetectionsApi>,
    saas_security_api: Box<dyn saas_security_api::SaasSecurityApi>,
    sample_uploads_api: Box<dyn sample_uploads_api::SampleUploadsApi>,
    scheduled_reports_api: Box<dyn scheduled_reports_api::ScheduledReportsApi>,
    sensor_download_api: Box<dyn sensor_download_api::SensorDownloadApi>,
    sensor_update_policies_api: Box<dyn sensor_update_policies_api::SensorUpdatePoliciesApi>,
    sensor_usage_api_api: Box<dyn sensor_usage_api_api::SensorUsageApiApi>,
    sensor_visibility_exclusions_api: Box<dyn sensor_visibility_exclusions_api::SensorVisibilityExclusionsApi>,
    serverless_vulnerabilities_api: Box<dyn serverless_vulnerabilities_api::ServerlessVulnerabilitiesApi>,
    spotlight_evaluation_logic_api: Box<dyn spotlight_evaluation_logic_api::SpotlightEvaluationLogicApi>,
    spotlight_vulnerabilities_api: Box<dyn spotlight_vulnerabilities_api::SpotlightVulnerabilitiesApi>,
    tailored_intelligence_api: Box<dyn tailored_intelligence_api::TailoredIntelligenceApi>,
    threatgraph_api: Box<dyn threatgraph_api::ThreatgraphApi>,
    unidentified_containers_api: Box<dyn unidentified_containers_api::UnidentifiedContainersApi>,
    user_management_api: Box<dyn user_management_api::UserManagementApi>,
    workflows_api: Box<dyn workflows_api::WorkflowsApi>,
    zero_trust_assessment_api: Box<dyn zero_trust_assessment_api::ZeroTrustAssessmentApi>,
}

impl ApiClient {
    pub fn new(configuration: Arc<configuration::Configuration>) -> Self {
        Self {
            aspm_api: Box::new(aspm_api::AspmApiClient::new(configuration.clone())),
            admission_control_policies_api: Box::new(admission_control_policies_api::AdmissionControlPoliciesApiClient::new(configuration.clone())),
            alerts_api: Box::new(alerts_api::AlertsApiClient::new(configuration.clone())),
            api_integrations_api: Box::new(api_integrations_api::ApiIntegrationsApiClient::new(configuration.clone())),
            cao_hunting_api: Box::new(cao_hunting_api::CaoHuntingApiClient::new(configuration.clone())),
            case_files_api: Box::new(case_files_api::CaseFilesApiClient::new(configuration.clone())),
            case_management_api: Box::new(case_management_api::CaseManagementApiClient::new(configuration.clone())),
            cases_api: Box::new(cases_api::CasesApiClient::new(configuration.clone())),
            certificate_based_exclusions_api: Box::new(certificate_based_exclusions_api::CertificateBasedExclusionsApiClient::new(configuration.clone())),
            cloud_aws_registration_api: Box::new(cloud_aws_registration_api::CloudAwsRegistrationApiClient::new(configuration.clone())),
            cloud_azure_registration_api: Box::new(cloud_azure_registration_api::CloudAzureRegistrationApiClient::new(configuration.clone())),
            cloud_connect_aws_api: Box::new(cloud_connect_aws_api::CloudConnectAwsApiClient::new(configuration.clone())),
            cloud_google_cloud_registration_api: Box::new(cloud_google_cloud_registration_api::CloudGoogleCloudRegistrationApiClient::new(configuration.clone())),
            cloud_oci_registration_api: Box::new(cloud_oci_registration_api::CloudOciRegistrationApiClient::new(configuration.clone())),
            cloud_policies_api: Box::new(cloud_policies_api::CloudPoliciesApiClient::new(configuration.clone())),
            cloud_security_api: Box::new(cloud_security_api::CloudSecurityApiClient::new(configuration.clone())),
            cloud_security_assets_api: Box::new(cloud_security_assets_api::CloudSecurityAssetsApiClient::new(configuration.clone())),
            cloud_security_compliance_api: Box::new(cloud_security_compliance_api::CloudSecurityComplianceApiClient::new(configuration.clone())),
            cloud_security_detections_api: Box::new(cloud_security_detections_api::CloudSecurityDetectionsApiClient::new(configuration.clone())),
            cloud_snapshots_api: Box::new(cloud_snapshots_api::CloudSnapshotsApiClient::new(configuration.clone())),
            configuration_assessment_api: Box::new(configuration_assessment_api::ConfigurationAssessmentApiClient::new(configuration.clone())),
            configuration_assessment_evaluation_logic_api: Box::new(configuration_assessment_evaluation_logic_api::ConfigurationAssessmentEvaluationLogicApiClient::new(configuration.clone())),
            container_alerts_api: Box::new(container_alerts_api::ContainerAlertsApiClient::new(configuration.clone())),
            container_detections_api: Box::new(container_detections_api::ContainerDetectionsApiClient::new(configuration.clone())),
            container_image_compliance_api: Box::new(container_image_compliance_api::ContainerImageComplianceApiClient::new(configuration.clone())),
            container_images_api: Box::new(container_images_api::ContainerImagesApiClient::new(configuration.clone())),
            container_packages_api: Box::new(container_packages_api::ContainerPackagesApiClient::new(configuration.clone())),
            container_vulnerabilities_api: Box::new(container_vulnerabilities_api::ContainerVulnerabilitiesApiClient::new(configuration.clone())),
            content_update_policies_api: Box::new(content_update_policies_api::ContentUpdatePoliciesApiClient::new(configuration.clone())),
            correlation_rules_api: Box::new(correlation_rules_api::CorrelationRulesApiClient::new(configuration.clone())),
            correlation_rules_admin_api: Box::new(correlation_rules_admin_api::CorrelationRulesAdminApiClient::new(configuration.clone())),
            cspg_iacapi_api: Box::new(cspg_iacapi_api::CspgIacapiApiClient::new(configuration.clone())),
            cspm_registration_api: Box::new(cspm_registration_api::CspmRegistrationApiClient::new(configuration.clone())),
            custom_ioa_api: Box::new(custom_ioa_api::CustomIoaApiClient::new(configuration.clone())),
            custom_storage_api: Box::new(custom_storage_api::CustomStorageApiClient::new(configuration.clone())),
            d4c_registration_api: Box::new(d4c_registration_api::D4cRegistrationApiClient::new(configuration.clone())),
            data_protection_configuration_api: Box::new(data_protection_configuration_api::DataProtectionConfigurationApiClient::new(configuration.clone())),
            default_api: Box::new(default_api::DefaultApiClient::new(configuration.clone())),
            delivery_settings_api: Box::new(delivery_settings_api::DeliverySettingsApiClient::new(configuration.clone())),
            deployments_api: Box::new(deployments_api::DeploymentsApiClient::new(configuration.clone())),
            detects_api: Box::new(detects_api::DetectsApiClient::new(configuration.clone())),
            device_content_api: Box::new(device_content_api::DeviceContentApiClient::new(configuration.clone())),
            device_control_policies_api: Box::new(device_control_policies_api::DeviceControlPoliciesApiClient::new(configuration.clone())),
            device_control_with_bluetooth_api: Box::new(device_control_with_bluetooth_api::DeviceControlWithBluetoothApiClient::new(configuration.clone())),
            discover_api: Box::new(discover_api::DiscoverApiClient::new(configuration.clone())),
            discover_iot_api: Box::new(discover_iot_api::DiscoverIotApiClient::new(configuration.clone())),
            downloads_api_api: Box::new(downloads_api_api::DownloadsApiApiClient::new(configuration.clone())),
            drift_indicators_api: Box::new(drift_indicators_api::DriftIndicatorsApiClient::new(configuration.clone())),
            event_schema_api: Box::new(event_schema_api::EventSchemaApiClient::new(configuration.clone())),
            event_streams_api: Box::new(event_streams_api::EventStreamsApiClient::new(configuration.clone())),
            execution_api: Box::new(execution_api::ExecutionApiClient::new(configuration.clone())),
            exposure_management_api: Box::new(exposure_management_api::ExposureManagementApiClient::new(configuration.clone())),
            falcon_complete_dashboard_api: Box::new(falcon_complete_dashboard_api::FalconCompleteDashboardApiClient::new(configuration.clone())),
            falcon_container_api: Box::new(falcon_container_api::FalconContainerApiClient::new(configuration.clone())),
            falcon_container_cli_api: Box::new(falcon_container_cli_api::FalconContainerCliApiClient::new(configuration.clone())),
            falcon_container_image_api: Box::new(falcon_container_image_api::FalconContainerImageApiClient::new(configuration.clone())),
            falconx_sandbox_api: Box::new(falconx_sandbox_api::FalconxSandboxApiClient::new(configuration.clone())),
            field_schema_api: Box::new(field_schema_api::FieldSchemaApiClient::new(configuration.clone())),
            filevantage_api: Box::new(filevantage_api::FilevantageApiClient::new(configuration.clone())),
            firewall_management_api: Box::new(firewall_management_api::FirewallManagementApiClient::new(configuration.clone())),
            firewall_policies_api: Box::new(firewall_policies_api::FirewallPoliciesApiClient::new(configuration.clone())),
            foundry_logscale_api: Box::new(foundry_logscale_api::FoundryLogscaleApiClient::new(configuration.clone())),
            host_group_api: Box::new(host_group_api::HostGroupApiClient::new(configuration.clone())),
            host_migration_api: Box::new(host_migration_api::HostMigrationApiClient::new(configuration.clone())),
            hosts_api: Box::new(hosts_api::HostsApiClient::new(configuration.clone())),
            identity_entities_api: Box::new(identity_entities_api::IdentityEntitiesApiClient::new(configuration.clone())),
            identity_protection_api: Box::new(identity_protection_api::IdentityProtectionApiClient::new(configuration.clone())),
            image_assessment_policies_api: Box::new(image_assessment_policies_api::ImageAssessmentPoliciesApiClient::new(configuration.clone())),
            incidents_api: Box::new(incidents_api::IncidentsApiClient::new(configuration.clone())),
            installation_tokens_api: Box::new(installation_tokens_api::InstallationTokensApiClient::new(configuration.clone())),
            installation_tokens_settings_api: Box::new(installation_tokens_settings_api::InstallationTokensSettingsApiClient::new(configuration.clone())),
            intel_api: Box::new(intel_api::IntelApiClient::new(configuration.clone())),
            intelligence_feeds_api: Box::new(intelligence_feeds_api::IntelligenceFeedsApiClient::new(configuration.clone())),
            intelligence_indicator_graph_api: Box::new(intelligence_indicator_graph_api::IntelligenceIndicatorGraphApiClient::new(configuration.clone())),
            ioa_exclusions_api: Box::new(ioa_exclusions_api::IoaExclusionsApiClient::new(configuration.clone())),
            ioc_api: Box::new(ioc_api::IocApiClient::new(configuration.clone())),
            iocs_api: Box::new(iocs_api::IocsApiClient::new(configuration.clone())),
            it_automation_api: Box::new(it_automation_api::ItAutomationApiClient::new(configuration.clone())),
            kubernetes_container_compliance_api: Box::new(kubernetes_container_compliance_api::KubernetesContainerComplianceApiClient::new(configuration.clone())),
            kubernetes_protection_api: Box::new(kubernetes_protection_api::KubernetesProtectionApiClient::new(configuration.clone())),
            lookup_files_api: Box::new(lookup_files_api::LookupFilesApiClient::new(configuration.clone())),
            malquery_api: Box::new(malquery_api::MalqueryApiClient::new(configuration.clone())),
            message_center_api: Box::new(message_center_api::MessageCenterApiClient::new(configuration.clone())),
            ml_exclusions_api: Box::new(ml_exclusions_api::MlExclusionsApiClient::new(configuration.clone())),
            mobile_enrollment_api: Box::new(mobile_enrollment_api::MobileEnrollmentApiClient::new(configuration.clone())),
            mssp_api: Box::new(mssp_api::MsspApiClient::new(configuration.clone())),
            ngsiem_api: Box::new(ngsiem_api::NgsiemApiClient::new(configuration.clone())),
            oauth2_api: Box::new(oauth2_api::Oauth2ApiClient::new(configuration.clone())),
            ods_api: Box::new(ods_api::OdsApiClient::new(configuration.clone())),
            prevention_policies_api: Box::new(prevention_policies_api::PreventionPoliciesApiClient::new(configuration.clone())),
            quarantine_api: Box::new(quarantine_api::QuarantineApiClient::new(configuration.clone())),
            quick_scan_api: Box::new(quick_scan_api::QuickScanApiClient::new(configuration.clone())),
            quick_scan_pro_api: Box::new(quick_scan_pro_api::QuickScanProApiClient::new(configuration.clone())),
            real_time_response_api: Box::new(real_time_response_api::RealTimeResponseApiClient::new(configuration.clone())),
            real_time_response_admin_api: Box::new(real_time_response_admin_api::RealTimeResponseAdminApiClient::new(configuration.clone())),
            real_time_response_audit_api: Box::new(real_time_response_audit_api::RealTimeResponseAuditApiClient::new(configuration.clone())),
            recon_api: Box::new(recon_api::ReconApiClient::new(configuration.clone())),
            release_notes_api: Box::new(release_notes_api::ReleaseNotesApiClient::new(configuration.clone())),
            releases_api: Box::new(releases_api::ReleasesApiClient::new(configuration.clone())),
            report_executions_api: Box::new(report_executions_api::ReportExecutionsApiClient::new(configuration.clone())),
            response_policies_api: Box::new(response_policies_api::ResponsePoliciesApiClient::new(configuration.clone())),
            runtime_detections_api: Box::new(runtime_detections_api::RuntimeDetectionsApiClient::new(configuration.clone())),
            saas_security_api: Box::new(saas_security_api::SaasSecurityApiClient::new(configuration.clone())),
            sample_uploads_api: Box::new(sample_uploads_api::SampleUploadsApiClient::new(configuration.clone())),
            scheduled_reports_api: Box::new(scheduled_reports_api::ScheduledReportsApiClient::new(configuration.clone())),
            sensor_download_api: Box::new(sensor_download_api::SensorDownloadApiClient::new(configuration.clone())),
            sensor_update_policies_api: Box::new(sensor_update_policies_api::SensorUpdatePoliciesApiClient::new(configuration.clone())),
            sensor_usage_api_api: Box::new(sensor_usage_api_api::SensorUsageApiApiClient::new(configuration.clone())),
            sensor_visibility_exclusions_api: Box::new(sensor_visibility_exclusions_api::SensorVisibilityExclusionsApiClient::new(configuration.clone())),
            serverless_vulnerabilities_api: Box::new(serverless_vulnerabilities_api::ServerlessVulnerabilitiesApiClient::new(configuration.clone())),
            spotlight_evaluation_logic_api: Box::new(spotlight_evaluation_logic_api::SpotlightEvaluationLogicApiClient::new(configuration.clone())),
            spotlight_vulnerabilities_api: Box::new(spotlight_vulnerabilities_api::SpotlightVulnerabilitiesApiClient::new(configuration.clone())),
            tailored_intelligence_api: Box::new(tailored_intelligence_api::TailoredIntelligenceApiClient::new(configuration.clone())),
            threatgraph_api: Box::new(threatgraph_api::ThreatgraphApiClient::new(configuration.clone())),
            unidentified_containers_api: Box::new(unidentified_containers_api::UnidentifiedContainersApiClient::new(configuration.clone())),
            user_management_api: Box::new(user_management_api::UserManagementApiClient::new(configuration.clone())),
            workflows_api: Box::new(workflows_api::WorkflowsApiClient::new(configuration.clone())),
            zero_trust_assessment_api: Box::new(zero_trust_assessment_api::ZeroTrustAssessmentApiClient::new(configuration.clone())),
        }
    }
}

impl Api for ApiClient {
    fn aspm_api(&self) -> &dyn aspm_api::AspmApi {
        self.aspm_api.as_ref()
    }
    fn admission_control_policies_api(
        &self,
    ) -> &dyn admission_control_policies_api::AdmissionControlPoliciesApi {
        self.admission_control_policies_api.as_ref()
    }
    fn alerts_api(&self) -> &dyn alerts_api::AlertsApi {
        self.alerts_api.as_ref()
    }
    fn api_integrations_api(&self) -> &dyn api_integrations_api::ApiIntegrationsApi {
        self.api_integrations_api.as_ref()
    }
    fn cao_hunting_api(&self) -> &dyn cao_hunting_api::CaoHuntingApi {
        self.cao_hunting_api.as_ref()
    }
    fn case_files_api(&self) -> &dyn case_files_api::CaseFilesApi {
        self.case_files_api.as_ref()
    }
    fn case_management_api(&self) -> &dyn case_management_api::CaseManagementApi {
        self.case_management_api.as_ref()
    }
    fn cases_api(&self) -> &dyn cases_api::CasesApi {
        self.cases_api.as_ref()
    }
    fn certificate_based_exclusions_api(
        &self,
    ) -> &dyn certificate_based_exclusions_api::CertificateBasedExclusionsApi {
        self.certificate_based_exclusions_api.as_ref()
    }
    fn cloud_aws_registration_api(
        &self,
    ) -> &dyn cloud_aws_registration_api::CloudAwsRegistrationApi {
        self.cloud_aws_registration_api.as_ref()
    }
    fn cloud_azure_registration_api(
        &self,
    ) -> &dyn cloud_azure_registration_api::CloudAzureRegistrationApi {
        self.cloud_azure_registration_api.as_ref()
    }
    fn cloud_connect_aws_api(&self) -> &dyn cloud_connect_aws_api::CloudConnectAwsApi {
        self.cloud_connect_aws_api.as_ref()
    }
    fn cloud_google_cloud_registration_api(
        &self,
    ) -> &dyn cloud_google_cloud_registration_api::CloudGoogleCloudRegistrationApi {
        self.cloud_google_cloud_registration_api.as_ref()
    }
    fn cloud_oci_registration_api(
        &self,
    ) -> &dyn cloud_oci_registration_api::CloudOciRegistrationApi {
        self.cloud_oci_registration_api.as_ref()
    }
    fn cloud_policies_api(&self) -> &dyn cloud_policies_api::CloudPoliciesApi {
        self.cloud_policies_api.as_ref()
    }
    fn cloud_security_api(&self) -> &dyn cloud_security_api::CloudSecurityApi {
        self.cloud_security_api.as_ref()
    }
    fn cloud_security_assets_api(&self) -> &dyn cloud_security_assets_api::CloudSecurityAssetsApi {
        self.cloud_security_assets_api.as_ref()
    }
    fn cloud_security_compliance_api(
        &self,
    ) -> &dyn cloud_security_compliance_api::CloudSecurityComplianceApi {
        self.cloud_security_compliance_api.as_ref()
    }
    fn cloud_security_detections_api(
        &self,
    ) -> &dyn cloud_security_detections_api::CloudSecurityDetectionsApi {
        self.cloud_security_detections_api.as_ref()
    }
    fn cloud_snapshots_api(&self) -> &dyn cloud_snapshots_api::CloudSnapshotsApi {
        self.cloud_snapshots_api.as_ref()
    }
    fn configuration_assessment_api(
        &self,
    ) -> &dyn configuration_assessment_api::ConfigurationAssessmentApi {
        self.configuration_assessment_api.as_ref()
    }
    fn configuration_assessment_evaluation_logic_api(
        &self,
    ) -> &dyn configuration_assessment_evaluation_logic_api::ConfigurationAssessmentEvaluationLogicApi
    {
        self.configuration_assessment_evaluation_logic_api.as_ref()
    }
    fn container_alerts_api(&self) -> &dyn container_alerts_api::ContainerAlertsApi {
        self.container_alerts_api.as_ref()
    }
    fn container_detections_api(&self) -> &dyn container_detections_api::ContainerDetectionsApi {
        self.container_detections_api.as_ref()
    }
    fn container_image_compliance_api(
        &self,
    ) -> &dyn container_image_compliance_api::ContainerImageComplianceApi {
        self.container_image_compliance_api.as_ref()
    }
    fn container_images_api(&self) -> &dyn container_images_api::ContainerImagesApi {
        self.container_images_api.as_ref()
    }
    fn container_packages_api(&self) -> &dyn container_packages_api::ContainerPackagesApi {
        self.container_packages_api.as_ref()
    }
    fn container_vulnerabilities_api(
        &self,
    ) -> &dyn container_vulnerabilities_api::ContainerVulnerabilitiesApi {
        self.container_vulnerabilities_api.as_ref()
    }
    fn content_update_policies_api(
        &self,
    ) -> &dyn content_update_policies_api::ContentUpdatePoliciesApi {
        self.content_update_policies_api.as_ref()
    }
    fn correlation_rules_api(&self) -> &dyn correlation_rules_api::CorrelationRulesApi {
        self.correlation_rules_api.as_ref()
    }
    fn correlation_rules_admin_api(
        &self,
    ) -> &dyn correlation_rules_admin_api::CorrelationRulesAdminApi {
        self.correlation_rules_admin_api.as_ref()
    }
    fn cspg_iacapi_api(&self) -> &dyn cspg_iacapi_api::CspgIacapiApi {
        self.cspg_iacapi_api.as_ref()
    }
    fn cspm_registration_api(&self) -> &dyn cspm_registration_api::CspmRegistrationApi {
        self.cspm_registration_api.as_ref()
    }
    fn custom_ioa_api(&self) -> &dyn custom_ioa_api::CustomIoaApi {
        self.custom_ioa_api.as_ref()
    }
    fn custom_storage_api(&self) -> &dyn custom_storage_api::CustomStorageApi {
        self.custom_storage_api.as_ref()
    }
    fn d4c_registration_api(&self) -> &dyn d4c_registration_api::D4cRegistrationApi {
        self.d4c_registration_api.as_ref()
    }
    fn data_protection_configuration_api(
        &self,
    ) -> &dyn data_protection_configuration_api::DataProtectionConfigurationApi {
        self.data_protection_configuration_api.as_ref()
    }
    fn default_api(&self) -> &dyn default_api::DefaultApi {
        self.default_api.as_ref()
    }
    fn delivery_settings_api(&self) -> &dyn delivery_settings_api::DeliverySettingsApi {
        self.delivery_settings_api.as_ref()
    }
    fn deployments_api(&self) -> &dyn deployments_api::DeploymentsApi {
        self.deployments_api.as_ref()
    }
    fn detects_api(&self) -> &dyn detects_api::DetectsApi {
        self.detects_api.as_ref()
    }
    fn device_content_api(&self) -> &dyn device_content_api::DeviceContentApi {
        self.device_content_api.as_ref()
    }
    fn device_control_policies_api(
        &self,
    ) -> &dyn device_control_policies_api::DeviceControlPoliciesApi {
        self.device_control_policies_api.as_ref()
    }
    fn device_control_with_bluetooth_api(
        &self,
    ) -> &dyn device_control_with_bluetooth_api::DeviceControlWithBluetoothApi {
        self.device_control_with_bluetooth_api.as_ref()
    }
    fn discover_api(&self) -> &dyn discover_api::DiscoverApi {
        self.discover_api.as_ref()
    }
    fn discover_iot_api(&self) -> &dyn discover_iot_api::DiscoverIotApi {
        self.discover_iot_api.as_ref()
    }
    fn downloads_api_api(&self) -> &dyn downloads_api_api::DownloadsApiApi {
        self.downloads_api_api.as_ref()
    }
    fn drift_indicators_api(&self) -> &dyn drift_indicators_api::DriftIndicatorsApi {
        self.drift_indicators_api.as_ref()
    }
    fn event_schema_api(&self) -> &dyn event_schema_api::EventSchemaApi {
        self.event_schema_api.as_ref()
    }
    fn event_streams_api(&self) -> &dyn event_streams_api::EventStreamsApi {
        self.event_streams_api.as_ref()
    }
    fn execution_api(&self) -> &dyn execution_api::ExecutionApi {
        self.execution_api.as_ref()
    }
    fn exposure_management_api(&self) -> &dyn exposure_management_api::ExposureManagementApi {
        self.exposure_management_api.as_ref()
    }
    fn falcon_complete_dashboard_api(
        &self,
    ) -> &dyn falcon_complete_dashboard_api::FalconCompleteDashboardApi {
        self.falcon_complete_dashboard_api.as_ref()
    }
    fn falcon_container_api(&self) -> &dyn falcon_container_api::FalconContainerApi {
        self.falcon_container_api.as_ref()
    }
    fn falcon_container_cli_api(&self) -> &dyn falcon_container_cli_api::FalconContainerCliApi {
        self.falcon_container_cli_api.as_ref()
    }
    fn falcon_container_image_api(
        &self,
    ) -> &dyn falcon_container_image_api::FalconContainerImageApi {
        self.falcon_container_image_api.as_ref()
    }
    fn falconx_sandbox_api(&self) -> &dyn falconx_sandbox_api::FalconxSandboxApi {
        self.falconx_sandbox_api.as_ref()
    }
    fn field_schema_api(&self) -> &dyn field_schema_api::FieldSchemaApi {
        self.field_schema_api.as_ref()
    }
    fn filevantage_api(&self) -> &dyn filevantage_api::FilevantageApi {
        self.filevantage_api.as_ref()
    }
    fn firewall_management_api(&self) -> &dyn firewall_management_api::FirewallManagementApi {
        self.firewall_management_api.as_ref()
    }
    fn firewall_policies_api(&self) -> &dyn firewall_policies_api::FirewallPoliciesApi {
        self.firewall_policies_api.as_ref()
    }
    fn foundry_logscale_api(&self) -> &dyn foundry_logscale_api::FoundryLogscaleApi {
        self.foundry_logscale_api.as_ref()
    }
    fn host_group_api(&self) -> &dyn host_group_api::HostGroupApi {
        self.host_group_api.as_ref()
    }
    fn host_migration_api(&self) -> &dyn host_migration_api::HostMigrationApi {
        self.host_migration_api.as_ref()
    }
    fn hosts_api(&self) -> &dyn hosts_api::HostsApi {
        self.hosts_api.as_ref()
    }
    fn identity_entities_api(&self) -> &dyn identity_entities_api::IdentityEntitiesApi {
        self.identity_entities_api.as_ref()
    }
    fn identity_protection_api(&self) -> &dyn identity_protection_api::IdentityProtectionApi {
        self.identity_protection_api.as_ref()
    }
    fn image_assessment_policies_api(
        &self,
    ) -> &dyn image_assessment_policies_api::ImageAssessmentPoliciesApi {
        self.image_assessment_policies_api.as_ref()
    }
    fn incidents_api(&self) -> &dyn incidents_api::IncidentsApi {
        self.incidents_api.as_ref()
    }
    fn installation_tokens_api(&self) -> &dyn installation_tokens_api::InstallationTokensApi {
        self.installation_tokens_api.as_ref()
    }
    fn installation_tokens_settings_api(
        &self,
    ) -> &dyn installation_tokens_settings_api::InstallationTokensSettingsApi {
        self.installation_tokens_settings_api.as_ref()
    }
    fn intel_api(&self) -> &dyn intel_api::IntelApi {
        self.intel_api.as_ref()
    }
    fn intelligence_feeds_api(&self) -> &dyn intelligence_feeds_api::IntelligenceFeedsApi {
        self.intelligence_feeds_api.as_ref()
    }
    fn intelligence_indicator_graph_api(
        &self,
    ) -> &dyn intelligence_indicator_graph_api::IntelligenceIndicatorGraphApi {
        self.intelligence_indicator_graph_api.as_ref()
    }
    fn ioa_exclusions_api(&self) -> &dyn ioa_exclusions_api::IoaExclusionsApi {
        self.ioa_exclusions_api.as_ref()
    }
    fn ioc_api(&self) -> &dyn ioc_api::IocApi {
        self.ioc_api.as_ref()
    }
    fn iocs_api(&self) -> &dyn iocs_api::IocsApi {
        self.iocs_api.as_ref()
    }
    fn it_automation_api(&self) -> &dyn it_automation_api::ItAutomationApi {
        self.it_automation_api.as_ref()
    }
    fn kubernetes_container_compliance_api(
        &self,
    ) -> &dyn kubernetes_container_compliance_api::KubernetesContainerComplianceApi {
        self.kubernetes_container_compliance_api.as_ref()
    }
    fn kubernetes_protection_api(&self) -> &dyn kubernetes_protection_api::KubernetesProtectionApi {
        self.kubernetes_protection_api.as_ref()
    }
    fn lookup_files_api(&self) -> &dyn lookup_files_api::LookupFilesApi {
        self.lookup_files_api.as_ref()
    }
    fn malquery_api(&self) -> &dyn malquery_api::MalqueryApi {
        self.malquery_api.as_ref()
    }
    fn message_center_api(&self) -> &dyn message_center_api::MessageCenterApi {
        self.message_center_api.as_ref()
    }
    fn ml_exclusions_api(&self) -> &dyn ml_exclusions_api::MlExclusionsApi {
        self.ml_exclusions_api.as_ref()
    }
    fn mobile_enrollment_api(&self) -> &dyn mobile_enrollment_api::MobileEnrollmentApi {
        self.mobile_enrollment_api.as_ref()
    }
    fn mssp_api(&self) -> &dyn mssp_api::MsspApi {
        self.mssp_api.as_ref()
    }
    fn ngsiem_api(&self) -> &dyn ngsiem_api::NgsiemApi {
        self.ngsiem_api.as_ref()
    }
    fn oauth2_api(&self) -> &dyn oauth2_api::Oauth2Api {
        self.oauth2_api.as_ref()
    }
    fn ods_api(&self) -> &dyn ods_api::OdsApi {
        self.ods_api.as_ref()
    }
    fn prevention_policies_api(&self) -> &dyn prevention_policies_api::PreventionPoliciesApi {
        self.prevention_policies_api.as_ref()
    }
    fn quarantine_api(&self) -> &dyn quarantine_api::QuarantineApi {
        self.quarantine_api.as_ref()
    }
    fn quick_scan_api(&self) -> &dyn quick_scan_api::QuickScanApi {
        self.quick_scan_api.as_ref()
    }
    fn quick_scan_pro_api(&self) -> &dyn quick_scan_pro_api::QuickScanProApi {
        self.quick_scan_pro_api.as_ref()
    }
    fn real_time_response_api(&self) -> &dyn real_time_response_api::RealTimeResponseApi {
        self.real_time_response_api.as_ref()
    }
    fn real_time_response_admin_api(
        &self,
    ) -> &dyn real_time_response_admin_api::RealTimeResponseAdminApi {
        self.real_time_response_admin_api.as_ref()
    }
    fn real_time_response_audit_api(
        &self,
    ) -> &dyn real_time_response_audit_api::RealTimeResponseAuditApi {
        self.real_time_response_audit_api.as_ref()
    }
    fn recon_api(&self) -> &dyn recon_api::ReconApi {
        self.recon_api.as_ref()
    }
    fn release_notes_api(&self) -> &dyn release_notes_api::ReleaseNotesApi {
        self.release_notes_api.as_ref()
    }
    fn releases_api(&self) -> &dyn releases_api::ReleasesApi {
        self.releases_api.as_ref()
    }
    fn report_executions_api(&self) -> &dyn report_executions_api::ReportExecutionsApi {
        self.report_executions_api.as_ref()
    }
    fn response_policies_api(&self) -> &dyn response_policies_api::ResponsePoliciesApi {
        self.response_policies_api.as_ref()
    }
    fn runtime_detections_api(&self) -> &dyn runtime_detections_api::RuntimeDetectionsApi {
        self.runtime_detections_api.as_ref()
    }
    fn saas_security_api(&self) -> &dyn saas_security_api::SaasSecurityApi {
        self.saas_security_api.as_ref()
    }
    fn sample_uploads_api(&self) -> &dyn sample_uploads_api::SampleUploadsApi {
        self.sample_uploads_api.as_ref()
    }
    fn scheduled_reports_api(&self) -> &dyn scheduled_reports_api::ScheduledReportsApi {
        self.scheduled_reports_api.as_ref()
    }
    fn sensor_download_api(&self) -> &dyn sensor_download_api::SensorDownloadApi {
        self.sensor_download_api.as_ref()
    }
    fn sensor_update_policies_api(
        &self,
    ) -> &dyn sensor_update_policies_api::SensorUpdatePoliciesApi {
        self.sensor_update_policies_api.as_ref()
    }
    fn sensor_usage_api_api(&self) -> &dyn sensor_usage_api_api::SensorUsageApiApi {
        self.sensor_usage_api_api.as_ref()
    }
    fn sensor_visibility_exclusions_api(
        &self,
    ) -> &dyn sensor_visibility_exclusions_api::SensorVisibilityExclusionsApi {
        self.sensor_visibility_exclusions_api.as_ref()
    }
    fn serverless_vulnerabilities_api(
        &self,
    ) -> &dyn serverless_vulnerabilities_api::ServerlessVulnerabilitiesApi {
        self.serverless_vulnerabilities_api.as_ref()
    }
    fn spotlight_evaluation_logic_api(
        &self,
    ) -> &dyn spotlight_evaluation_logic_api::SpotlightEvaluationLogicApi {
        self.spotlight_evaluation_logic_api.as_ref()
    }
    fn spotlight_vulnerabilities_api(
        &self,
    ) -> &dyn spotlight_vulnerabilities_api::SpotlightVulnerabilitiesApi {
        self.spotlight_vulnerabilities_api.as_ref()
    }
    fn tailored_intelligence_api(&self) -> &dyn tailored_intelligence_api::TailoredIntelligenceApi {
        self.tailored_intelligence_api.as_ref()
    }
    fn threatgraph_api(&self) -> &dyn threatgraph_api::ThreatgraphApi {
        self.threatgraph_api.as_ref()
    }
    fn unidentified_containers_api(
        &self,
    ) -> &dyn unidentified_containers_api::UnidentifiedContainersApi {
        self.unidentified_containers_api.as_ref()
    }
    fn user_management_api(&self) -> &dyn user_management_api::UserManagementApi {
        self.user_management_api.as_ref()
    }
    fn workflows_api(&self) -> &dyn workflows_api::WorkflowsApi {
        self.workflows_api.as_ref()
    }
    fn zero_trust_assessment_api(&self) -> &dyn zero_trust_assessment_api::ZeroTrustAssessmentApi {
        self.zero_trust_assessment_api.as_ref()
    }
}
