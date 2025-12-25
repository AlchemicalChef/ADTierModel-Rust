//! Tauri commands for GPO management

use crate::domain::Tier;
use crate::infrastructure::{
    GpoConfigResult, TierGpoStatus, get_domain_dn,
    get_all_gpo_status, configure_tier_gpos, configure_all_tier_gpos, delete_tier_gpos,
};

/// Get the GPO status for all tiers
#[tauri::command]
pub async fn get_gpo_status() -> Result<Vec<TierGpoStatus>, String> {
    let domain_dn = get_domain_dn()?;
    get_all_gpo_status(&domain_dn).map_err(|e| format!("Failed to get GPO status: {}", e))
}

/// Configure GPOs for a specific tier
#[tauri::command]
pub async fn configure_tier_gpo(tier_name: String) -> Result<GpoConfigResult, String> {
    let tier = match tier_name.as_str() {
        "Tier0" => Tier::Tier0,
        "Tier1" => Tier::Tier1,
        "Tier2" => Tier::Tier2,
        _ => return Err(format!("Invalid tier: {}", tier_name)),
    };

    let domain_dn = get_domain_dn()?;
    configure_tier_gpos(tier, &domain_dn).map_err(|e| format!("Failed to configure GPOs: {}", e))
}

/// Configure GPOs for all tiers
#[tauri::command]
pub async fn configure_all_gpos() -> Result<GpoConfigResult, String> {
    let domain_dn = get_domain_dn()?;
    configure_all_tier_gpos(&domain_dn).map_err(|e| format!("Failed to configure GPOs: {}", e))
}

/// Delete GPOs for a specific tier
#[tauri::command]
pub async fn delete_tier_gpo(tier_name: String) -> Result<Vec<String>, String> {
    let tier = match tier_name.as_str() {
        "Tier0" => Tier::Tier0,
        "Tier1" => Tier::Tier1,
        "Tier2" => Tier::Tier2,
        _ => return Err(format!("Invalid tier: {}", tier_name)),
    };

    let domain_dn = get_domain_dn()?;
    delete_tier_gpos(tier, &domain_dn).map_err(|e| format!("Failed to delete GPOs: {}", e))
}
