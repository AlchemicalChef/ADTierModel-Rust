//! Compliance checking Tauri commands

use serde::{Deserialize, Serialize};
use crate::domain::{ComplianceStatus, CrossTierAccess};
use crate::infrastructure::{
    check_cross_tier_access, get_compliance_status as infra_get_compliance_status,
    get_domain_dn, bulk_disable_accounts, bulk_harden_service_accounts,
};

/// Get overall compliance status
///
/// # Arguments
/// * `stale_threshold_days` - Optional number of days to consider an account stale (defaults to 90)
#[tauri::command]
pub async fn get_compliance_status(stale_threshold_days: Option<u32>) -> Result<ComplianceStatus, String> {
    let domain_dn = get_domain_dn()?;
    let threshold = stale_threshold_days.unwrap_or(90);
    infra_get_compliance_status(&domain_dn, threshold)
}

/// Get cross-tier access violations specifically
#[tauri::command]
pub async fn get_cross_tier_violations() -> Result<Vec<CrossTierAccess>, String> {
    let domain_dn = get_domain_dn()?;
    check_cross_tier_access(&domain_dn)
}

/// Result of bulk disable operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkDisableResult {
    pub success_count: usize,
    pub failure_count: usize,
    pub disabled_accounts: Vec<String>,
    pub errors: Vec<String>,
}

/// Bulk disable stale or violating accounts
#[tauri::command]
pub async fn bulk_disable_stale_accounts(object_dns: Vec<String>) -> Result<BulkDisableResult, String> {
    let results = bulk_disable_accounts(&object_dns);

    let mut disabled = Vec::new();
    let mut errors = Vec::new();

    for result in results {
        match result {
            Ok(dn) => disabled.push(dn),
            Err(e) => errors.push(e),
        }
    }

    Ok(BulkDisableResult {
        success_count: disabled.len(),
        failure_count: errors.len(),
        disabled_accounts: disabled,
        errors,
    })
}

/// Result of security hardening operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardenAccountsResult {
    pub success_count: usize,
    pub failure_count: usize,
    pub hardened_accounts: Vec<String>,
    pub errors: Vec<String>,
}

/// Harden service accounts by marking them as sensitive (cannot be delegated)
#[tauri::command]
pub async fn harden_service_accounts(object_dns: Vec<String>) -> Result<HardenAccountsResult, String> {
    let results = bulk_harden_service_accounts(&object_dns);

    let mut hardened = Vec::new();
    let mut errors = Vec::new();

    for result in results {
        match result {
            Ok(dn) => hardened.push(dn),
            Err(e) => errors.push(e),
        }
    }

    Ok(HardenAccountsResult {
        success_count: hardened.len(),
        failure_count: errors.len(),
        hardened_accounts: hardened,
        errors,
    })
}
