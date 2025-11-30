//! Tauri commands for endpoint protection GPO management

use crate::domain::Tier;
use crate::infrastructure::endpoint_protection::{
    self, EndpointGpoConfigResult, EndpointGpoStatus, EndpointGpoType,
};
use crate::infrastructure::get_domain_dn;

/// Get status of all endpoint protection GPOs
#[tauri::command]
pub async fn get_endpoint_protection_status() -> Result<Vec<EndpointGpoStatus>, String> {
    let domain_dn = get_domain_dn().map_err(|e| e.to_string())?;
    endpoint_protection::get_all_endpoint_gpo_status(&domain_dn).map_err(|e| e.to_string())
}

/// Configure an endpoint protection GPO
#[tauri::command]
pub async fn configure_endpoint_gpo(
    gpo_type: String,
    tier: Option<String>,
) -> Result<EndpointGpoConfigResult, String> {
    let domain_dn = get_domain_dn().map_err(|e| e.to_string())?;

    let tier_enum = tier.as_ref().and_then(|t| match t.as_str() {
        "Tier0" => Some(Tier::Tier0),
        "Tier1" => Some(Tier::Tier1),
        "Tier2" => Some(Tier::Tier2),
        _ => None,
    });

    match gpo_type.as_str() {
        "AuditBaseline" => {
            if let Some(t) = tier_enum {
                endpoint_protection::configure_audit_baseline_gpo(t, &domain_dn)
                    .map_err(|e| e.to_string())
            } else {
                Err("Tier is required for AuditBaseline GPO".to_string())
            }
        }
        "AuditEnhanced" => {
            if let Some(t) = tier_enum {
                endpoint_protection::configure_audit_enhanced_gpo(t, &domain_dn)
                    .map_err(|e| e.to_string())
            } else {
                Err("Tier is required for AuditEnhanced GPO".to_string())
            }
        }
        "DcAuditEssential" => {
            endpoint_protection::configure_dc_audit_essential_gpo(&domain_dn)
                .map_err(|e| e.to_string())
        }
        "DcAuditComprehensive" => {
            endpoint_protection::configure_dc_audit_comprehensive_gpo(&domain_dn)
                .map_err(|e| e.to_string())
        }
        "DefenderProtection" => {
            endpoint_protection::configure_defender_gpo(&domain_dn).map_err(|e| e.to_string())
        }
        _ => Err(format!("Unknown GPO type: {}", gpo_type)),
    }
}

/// Configure all endpoint protection GPOs
#[tauri::command]
pub async fn configure_all_endpoint_gpos() -> Result<Vec<EndpointGpoConfigResult>, String> {
    let domain_dn = get_domain_dn().map_err(|e| e.to_string())?;
    let mut results = Vec::new();

    // Configure per-tier audit GPOs
    for tier in Tier::all() {
        // Baseline audit
        match endpoint_protection::configure_audit_baseline_gpo(*tier, &domain_dn) {
            Ok(result) => results.push(result),
            Err(e) => {
                let mut result =
                    EndpointGpoConfigResult::new("AuditBaseline", &format!("SEC-{}-Audit-Baseline", tier));
                result.add_error(e.to_string());
                results.push(result);
            }
        }

        // Enhanced audit
        match endpoint_protection::configure_audit_enhanced_gpo(*tier, &domain_dn) {
            Ok(result) => results.push(result),
            Err(e) => {
                let mut result =
                    EndpointGpoConfigResult::new("AuditEnhanced", &format!("SEC-{}-Audit-Enhanced", tier));
                result.add_error(e.to_string());
                results.push(result);
            }
        }
    }

    // Configure DC audit GPOs
    match endpoint_protection::configure_dc_audit_essential_gpo(&domain_dn) {
        Ok(result) => results.push(result),
        Err(e) => {
            let mut result = EndpointGpoConfigResult::new("DcAuditEssential", "SEC-DC-Audit-Essential");
            result.add_error(e.to_string());
            results.push(result);
        }
    }

    match endpoint_protection::configure_dc_audit_comprehensive_gpo(&domain_dn) {
        Ok(result) => results.push(result),
        Err(e) => {
            let mut result =
                EndpointGpoConfigResult::new("DcAuditComprehensive", "SEC-DC-Audit-Comprehensive");
            result.add_error(e.to_string());
            results.push(result);
        }
    }

    // Configure Defender GPO
    match endpoint_protection::configure_defender_gpo(&domain_dn) {
        Ok(result) => results.push(result),
        Err(e) => {
            let mut result = EndpointGpoConfigResult::new("DefenderProtection", "SEC-Defender-Protection");
            result.add_error(e.to_string());
            results.push(result);
        }
    }

    Ok(results)
}

/// Delete an endpoint protection GPO
#[tauri::command]
pub async fn delete_endpoint_gpo_cmd(
    gpo_type: String,
    tier: Option<String>,
) -> Result<(), String> {
    let tier_enum = tier.as_ref().and_then(|t| match t.as_str() {
        "Tier0" => Some(Tier::Tier0),
        "Tier1" => Some(Tier::Tier1),
        "Tier2" => Some(Tier::Tier2),
        _ => None,
    });

    let gpo_type_enum = match gpo_type.as_str() {
        "AuditBaseline" => EndpointGpoType::AuditBaseline,
        "AuditEnhanced" => EndpointGpoType::AuditEnhanced,
        "DcAuditEssential" => EndpointGpoType::DcAuditEssential,
        "DcAuditComprehensive" => EndpointGpoType::DcAuditComprehensive,
        "DefenderProtection" => EndpointGpoType::DefenderProtection,
        _ => return Err(format!("Unknown GPO type: {}", gpo_type)),
    };

    endpoint_protection::delete_endpoint_gpo(gpo_type_enum, tier_enum).map_err(|e| e.to_string())
}
