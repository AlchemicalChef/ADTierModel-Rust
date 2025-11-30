//! Tauri commands for tier management
//!
//! These commands provide the interface between the frontend and AD operations.
//! This module requires Windows - all AD operations use Windows ADSI.

use crate::domain::{
    DomainInfo, GroupSuffix, InitializationOptions, InitializationResult, InitializationStatus,
    SubOU, Tier, Tier0Component, TierCounts, TierMember,
};
use crate::infrastructure::{
    AdConnection, add_group_member, check_initialization_status, create_admin_user,
    discover_tier0_infrastructure, get_tier_objects, initialize_tier_model, move_ad_object,
    remove_group_member, test_ad_connection, AdDiagnostics,
};
use once_cell::sync::Lazy;
use std::sync::Mutex;

/// Cached AD connection
static AD_CONNECTION: Lazy<Mutex<Option<AdConnection>>> = Lazy::new(|| Mutex::new(None));

/// Get or create AD connection
fn get_connection() -> Result<std::sync::MutexGuard<'static, Option<AdConnection>>, String> {
    let mut conn = AD_CONNECTION.lock().map_err(|e| {
        tracing::error!(error = %e, "Failed to acquire AD connection lock");
        format!("Lock error: {}", e)
    })?;

    if conn.is_none() {
        tracing::debug!("No existing AD connection, attempting to connect");
        match AdConnection::connect() {
            Ok(c) => {
                tracing::info!("AD connection established");
                *conn = Some(c);
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to connect to AD");
                return Err(format!("Failed to connect to AD: {}", e));
            }
        }
    }

    Ok(conn)
}

/// Get domain connection info
#[tauri::command]
pub async fn get_domain_info() -> Result<DomainInfo, String> {
    let conn = get_connection()?;
    match conn.as_ref() {
        Some(c) => Ok(c.get_domain_info()),
        None => Err("Not connected to Active Directory".to_string()),
    }
}

/// Diagnose AD connection - returns detailed diagnostic info for debugging
#[tauri::command]
pub async fn diagnose_ad_connection() -> Result<AdDiagnostics, String> {
    // First try to get the domain DN from existing connection
    let domain_dn = {
        let conn = AD_CONNECTION.lock().map_err(|e| format!("Lock error: {}", e))?;
        match conn.as_ref() {
            Some(c) => c.domain_dn.clone(),
            None => {
                // Try to establish connection first to get domain DN
                drop(conn);
                match AdConnection::connect() {
                    Ok(c) => {
                        let dn = c.domain_dn.clone();
                        let mut conn = AD_CONNECTION.lock().map_err(|e| format!("Lock error: {}", e))?;
                        *conn = Some(c);
                        dn
                    }
                    Err(e) => {
                        // Can't connect, try to discover domain DN another way
                        // Return diagnostics showing the connection failure
                        return Ok(AdDiagnostics {
                            domain_dn: "Unknown - connection failed".to_string(),
                            com_init_status: "Not tested".to_string(),
                            ldap_bind_status: "Not tested".to_string(),
                            ldap_search_status: "Not tested".to_string(),
                            objects_found: 0,
                            error_code: None,
                            error_message: Some(format!("Initial connection failed: {}", e)),
                            steps_completed: vec![format!("AdConnection::connect() failed: {}", e)],
                            tier_ou_status: Vec::new(),
                        });
                    }
                }
            }
        }
    };

    // Run the diagnostic test in a separate thread to prevent hanging the async runtime
    let dn = domain_dn.clone();
    let handle = std::thread::spawn(move || {
        test_ad_connection(&dn)
    });

    // Wait for the thread with a timeout
    match handle.join() {
        Ok(result) => Ok(result),
        Err(_) => Ok(AdDiagnostics {
            domain_dn,
            com_init_status: "Unknown".to_string(),
            ldap_bind_status: "Unknown".to_string(),
            ldap_search_status: "Unknown".to_string(),
            objects_found: 0,
            error_code: Some("THREAD_PANIC".to_string()),
            error_message: Some("Diagnostic thread panicked".to_string()),
            steps_completed: vec!["Thread panicked during diagnostics".to_string()],
            tier_ou_status: Vec::new(),
        }),
    }
}

/// Get tier counts for all tiers
#[tauri::command]
pub async fn get_tier_counts() -> Result<TierCounts, String> {
    let conn = get_connection()?;
    let domain_dn = match conn.as_ref() {
        Some(c) => c.domain_dn.clone(),
        None => return Err("Not connected".to_string()),
    };
    drop(conn); // Release lock before queries

    // Run all blocking LDAP queries in a separate thread to prevent blocking async runtime
    let handle = std::thread::spawn(move || {
        let tier0 = match get_tier_objects(&domain_dn, Some(Tier::Tier0)) {
            Ok(v) => v.len(),
            Err(e) => {
                tracing::warn!(error = %e, "Tier0 query failed (OU may not exist)");
                0
            }
        };
        let tier1 = match get_tier_objects(&domain_dn, Some(Tier::Tier1)) {
            Ok(v) => v.len(),
            Err(e) => {
                tracing::warn!(error = %e, "Tier1 query failed (OU may not exist)");
                0
            }
        };
        let tier2 = match get_tier_objects(&domain_dn, Some(Tier::Tier2)) {
            Ok(v) => v.len(),
            Err(e) => {
                tracing::warn!(error = %e, "Tier2 query failed (OU may not exist)");
                0
            }
        };
        let unassigned = match get_tier_objects(&domain_dn, None) {
            Ok(v) => v.len(),
            Err(e) => {
                tracing::error!(error = %e, "Unassigned query failed - this searches entire domain");
                0
            }
        };

        tracing::info!(
            tier0 = tier0,
            tier1 = tier1,
            tier2 = tier2,
            unassigned = unassigned,
            "Tier counts retrieved"
        );

        TierCounts {
            tier0,
            tier1,
            tier2,
            unassigned,
        }
    });

    handle.join()
        .map_err(|_| "Tier counts query thread panicked".to_string())
}

/// Get members of a specific tier
#[tauri::command]
pub async fn get_tier_members(tier_name: String) -> Result<Vec<TierMember>, String> {
    let tier = match tier_name.as_str() {
        "Tier0" => Some(Tier::Tier0),
        "Tier1" => Some(Tier::Tier1),
        "Tier2" => Some(Tier::Tier2),
        "Unassigned" => None,
        _ => return Err(format!("Invalid tier: {}", tier_name)),
    };

    let conn = get_connection()?;
    let domain_dn = match conn.as_ref() {
        Some(c) => c.domain_dn.clone(),
        None => return Err("Not connected".to_string()),
    };
    drop(conn); // Release lock before query

    // Run blocking LDAP query in separate thread to prevent blocking async runtime
    let handle = std::thread::spawn(move || {
        get_tier_objects(&domain_dn, tier)
    });

    handle.join()
        .map_err(|_| "Query thread panicked".to_string())?
        .map_err(|e| format!("Query failed: {}", e))
}

/// Get Tier 0 infrastructure components
#[tauri::command]
pub async fn get_tier0_infrastructure() -> Result<Vec<Tier0Component>, String> {
    let conn = get_connection()?;
    let domain_dn = match conn.as_ref() {
        Some(c) => c.domain_dn.clone(),
        None => return Err("Not connected".to_string()),
    };
    drop(conn); // Release lock before query

    // Run blocking LDAP query in separate thread to prevent blocking async runtime
    let handle = std::thread::spawn(move || {
        discover_tier0_infrastructure(&domain_dn)
    });

    handle.join()
        .map_err(|_| "Discovery thread panicked".to_string())?
        .map_err(|e| format!("Discovery failed: {}", e))
}

/// Force reconnection to AD
#[tauri::command]
pub async fn reconnect_ad() -> Result<DomainInfo, String> {
    tracing::info!("Command: reconnect_ad - Forcing AD reconnection");
    let mut conn = AD_CONNECTION.lock().map_err(|e| {
        tracing::error!(error = %e, "Failed to acquire lock for reconnection");
        format!("Lock error: {}", e)
    })?;
    *conn = None; // Clear existing connection
    tracing::debug!("Cleared existing AD connection");

    match AdConnection::connect() {
        Ok(c) => {
            let info = c.get_domain_info();
            tracing::info!(domain = info.dns_root.as_str(), "AD reconnection successful");
            *conn = Some(c);
            Ok(info)
        }
        Err(e) => {
            tracing::error!(error = %e, "AD reconnection failed");
            Err(format!("Reconnection failed: {}", e))
        }
    }
}

// ============================================================================
// Initialization Commands
// ============================================================================

/// Check if the tier model has been initialized
#[tauri::command]
pub async fn check_tier_initialization() -> Result<InitializationStatus, String> {
    let conn = get_connection()?;
    let domain_dn = match conn.as_ref() {
        Some(c) => c.domain_dn.clone(),
        None => return Err("Not connected".to_string()),
    };
    drop(conn);

    check_initialization_status(&domain_dn).map_err(|e| format!("Check failed: {}", e))
}

/// Initialize the AD Tier Model structure
#[tauri::command]
pub async fn initialize_ad_tier_model(
    options: InitializationOptions,
) -> Result<InitializationResult, String> {
    tracing::info!(
        create_ou = options.create_ou_structure,
        create_groups = options.create_groups,
        set_permissions = options.set_permissions,
        create_gpos = options.create_gpos,
        "Command: initialize_ad_tier_model"
    );

    let conn = get_connection()?;
    let domain_dn = match conn.as_ref() {
        Some(c) => c.domain_dn.clone(),
        None => return Err("Not connected".to_string()),
    };
    drop(conn);

    let result = initialize_tier_model(&domain_dn, &options).map_err(|e| {
        tracing::error!(error = %e, "Tier model initialization failed");
        format!("Initialization failed: {}", e)
    });
    if result.is_ok() {
        tracing::info!("Tier model initialization completed successfully");
    }
    result
}

/// Get the expected OU structure that will be created
#[tauri::command]
pub async fn get_expected_ou_structure() -> Result<Vec<String>, String> {
    let conn = get_connection()?;
    let domain_dn = match conn.as_ref() {
        Some(c) => c.domain_dn.clone(),
        None => return Err("Not connected".to_string()),
    };
    drop(conn);

    let mut ous = Vec::new();

    for tier in Tier::all() {
        ous.push(format!("OU={},{}", tier, domain_dn));
        for sub_ou in SubOU::all() {
            ous.push(format!("OU={},OU={},{}", sub_ou.as_str(), tier, domain_dn));
        }
    }

    Ok(ous)
}

/// Get the expected groups that will be created
#[tauri::command]
pub async fn get_expected_groups() -> Result<Vec<String>, String> {
    let mut groups = Vec::new();

    for tier in Tier::all() {
        for suffix in GroupSuffix::all() {
            groups.push(format!("{}-{}", tier, suffix.as_str()));
        }
    }

    Ok(groups)
}

// ============================================================================
// Write Operations - Move and Group Management
// ============================================================================

/// Move an AD object to a specific tier
#[tauri::command]
pub async fn move_object_to_tier(
    object_dn: String,
    target_tier: String,
    sub_ou: Option<String>,
) -> Result<String, String> {
    tracing::info!(
        object_dn = object_dn.as_str(),
        target_tier = target_tier.as_str(),
        sub_ou = ?sub_ou,
        "Command: move_object_to_tier"
    );
    let tier = match target_tier.as_str() {
        "Tier0" => Tier::Tier0,
        "Tier1" => Tier::Tier1,
        "Tier2" => Tier::Tier2,
        _ => {
            tracing::warn!(tier = target_tier.as_str(), "Invalid tier specified");
            return Err(format!("Invalid tier: {}", target_tier));
        }
    };

    let sub = sub_ou
        .as_deref()
        .map(|s| match s {
            "Users" => Some(SubOU::Users),
            "Computers" => Some(SubOU::Computers),
            "Groups" => Some(SubOU::Groups),
            "ServiceAccounts" => Some(SubOU::ServiceAccounts),
            "AdminWorkstations" => Some(SubOU::AdminWorkstations),
            _ => None,
        })
        .flatten();

    let conn = get_connection()?;
    let domain_dn = match conn.as_ref() {
        Some(c) => c.domain_dn.clone(),
        None => return Err("Not connected".to_string()),
    };
    drop(conn);

    // Build target OU path
    let target_ou = if let Some(sub_ou) = sub {
        format!("OU={},OU={},{}", sub_ou.as_str(), tier, domain_dn)
    } else {
        format!("OU={},{}", tier, domain_dn)
    };

    move_ad_object(&object_dn, &target_ou).map_err(|e| format!("Move failed: {}", e))
}

/// Add a member to a tier group
#[tauri::command]
pub async fn add_to_tier_group(
    member_dn: String,
    tier_name: String,
    group_suffix: String,
) -> Result<(), String> {
    let tier = match tier_name.as_str() {
        "Tier0" => Tier::Tier0,
        "Tier1" => Tier::Tier1,
        "Tier2" => Tier::Tier2,
        _ => return Err(format!("Invalid tier: {}", tier_name)),
    };

    let suffix = match group_suffix.as_str() {
        "Admins" => GroupSuffix::Admins,
        "Operators" => GroupSuffix::Operators,
        "Readers" => GroupSuffix::Readers,
        "ServiceAccounts" => GroupSuffix::ServiceAccounts,
        "JumpServers" => GroupSuffix::JumpServers,
        _ => return Err(format!("Invalid group suffix: {}. Valid values: Admins, Operators, Readers, ServiceAccounts, JumpServers", group_suffix)),
    };

    let conn = get_connection()?;
    let domain_dn = match conn.as_ref() {
        Some(c) => c.domain_dn.clone(),
        None => return Err("Not connected".to_string()),
    };
    drop(conn);

    let group_dn = crate::domain::tier_group_dn(tier, suffix, &domain_dn);

    add_group_member(&group_dn, &member_dn).map_err(|e| format!("Failed to add member: {}", e))
}

/// Remove a member from a tier group
#[tauri::command]
pub async fn remove_from_tier_group(
    member_dn: String,
    tier_name: String,
    group_suffix: String,
) -> Result<(), String> {
    let tier = match tier_name.as_str() {
        "Tier0" => Tier::Tier0,
        "Tier1" => Tier::Tier1,
        "Tier2" => Tier::Tier2,
        _ => return Err(format!("Invalid tier: {}", tier_name)),
    };

    let suffix = match group_suffix.as_str() {
        "Admins" => GroupSuffix::Admins,
        "Operators" => GroupSuffix::Operators,
        "Readers" => GroupSuffix::Readers,
        "ServiceAccounts" => GroupSuffix::ServiceAccounts,
        "JumpServers" => GroupSuffix::JumpServers,
        _ => return Err(format!("Invalid group suffix: {}. Valid values: Admins, Operators, Readers, ServiceAccounts, JumpServers", group_suffix)),
    };

    let conn = get_connection()?;
    let domain_dn = match conn.as_ref() {
        Some(c) => c.domain_dn.clone(),
        None => return Err("Not connected".to_string()),
    };
    drop(conn);

    let group_dn = crate::domain::tier_group_dn(tier, suffix, &domain_dn);

    remove_group_member(&group_dn, &member_dn).map_err(|e| format!("Failed to remove member: {}", e))
}

/// Move a Tier 0 infrastructure component to the correct location
#[tauri::command]
pub async fn move_tier0_component(
    object_dn: String,
    role_type: String,
) -> Result<String, String> {
    // Determine the correct sub-OU based on role type
    let sub_ou = match role_type.as_str() {
        "DomainController" => {
            // DCs stay in Domain Controllers OU (not moved)
            return Err("Domain Controllers should remain in the default Domain Controllers OU".to_string());
        }
        "PAW" => SubOU::AdminWorkstations,
        _ => SubOU::Computers, // ADFS, EntraConnect, CertificateAuthority
    };

    let conn = get_connection()?;
    let domain_dn = match conn.as_ref() {
        Some(c) => c.domain_dn.clone(),
        None => return Err("Not connected".to_string()),
    };
    drop(conn);

    let target_ou = format!("OU={},OU=Tier0,{}", sub_ou.as_str(), domain_dn);

    move_ad_object(&object_dn, &target_ou)
        .map_err(|e| format!("Failed to move Tier 0 component: {}", e))
}

// ============================================================================
// Admin Account Creation
// ============================================================================

/// Options for creating a new admin account
#[derive(serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreateAdminAccountOptions {
    /// Base username (without tier prefix)
    pub base_username: String,
    /// Display name for the account
    pub display_name: String,
    /// Target tier for the account
    pub target_tier: String,
    /// Account type: "admin" or "service"
    pub account_type: String,
    /// Optional description
    pub description: Option<String>,
    /// Password for the account
    pub password: String,
    /// Groups to add the account to
    pub groups: Vec<String>,
    /// Whether to enable the account immediately
    pub enabled: bool,
}

/// Result from creating an admin account
#[derive(serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreateAdminAccountResult {
    pub success: bool,
    pub account_dn: Option<String>,
    pub sam_account_name: String,
    pub groups_added: Vec<String>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

/// Create a new tiered admin account
#[tauri::command]
pub async fn create_admin_account(
    options: CreateAdminAccountOptions,
) -> Result<CreateAdminAccountResult, String> {
    tracing::info!(
        base_username = options.base_username.as_str(),
        target_tier = options.target_tier.as_str(),
        account_type = options.account_type.as_str(),
        "Command: create_admin_account"
    );
    let tier = match options.target_tier.as_str() {
        "Tier0" => Tier::Tier0,
        "Tier1" => Tier::Tier1,
        "Tier2" => Tier::Tier2,
        _ => {
            tracing::warn!(tier = options.target_tier.as_str(), "Invalid tier for account creation");
            return Err(format!("Invalid tier: {}", options.target_tier));
        }
    };

    // Generate the SAM account name with tier prefix
    let sam_account_name = match options.account_type.as_str() {
        "admin" => format!("adm-t{}-{}", tier.to_string().chars().last().unwrap(), options.base_username),
        "service" => format!("svc-t{}-{}", tier.to_string().chars().last().unwrap(), options.base_username),
        _ => return Err(format!("Invalid account type: {}. Use 'admin' or 'service'", options.account_type)),
    };

    let conn = get_connection()?;
    let domain_dn = match conn.as_ref() {
        Some(c) => c.domain_dn.clone(),
        None => return Err("Not connected".to_string()),
    };
    drop(conn);

    // Determine target OU based on account type
    let sub_ou = match options.account_type.as_str() {
        "admin" => SubOU::Users,
        "service" => SubOU::ServiceAccounts,
        _ => SubOU::Users,
    };

    let target_ou = format!("OU={},OU={},{}", sub_ou.as_str(), tier, domain_dn);

    // Create the account
    match create_admin_user(
        &target_ou,
        &sam_account_name,
        &options.display_name,
        options.description.as_deref(),
        &options.password,
        options.enabled,
    ) {
        Ok(account_dn) => {
            let mut result = CreateAdminAccountResult {
                success: true,
                account_dn: Some(account_dn.clone()),
                sam_account_name: sam_account_name.clone(),
                groups_added: Vec::new(),
                warnings: Vec::new(),
                error: None,
            };

            // Add to requested groups
            for group_suffix in &options.groups {
                let suffix = match group_suffix.as_str() {
                    "Admins" => GroupSuffix::Admins,
                    "Operators" => GroupSuffix::Operators,
                    "Readers" => GroupSuffix::Readers,
                    "ServiceAccounts" => GroupSuffix::ServiceAccounts,
                    "JumpServers" => GroupSuffix::JumpServers,
                    _ => {
                        result.warnings.push(format!("Unknown group suffix: {}", group_suffix));
                        continue;
                    }
                };

                let group_dn = crate::domain::tier_group_dn(tier, suffix, &domain_dn);
                match add_group_member(&group_dn, &account_dn) {
                    Ok(_) => result.groups_added.push(format!("{}-{}", tier, group_suffix)),
                    Err(e) => result.warnings.push(format!("Failed to add to {}-{}: {}", tier, group_suffix, e)),
                }
            }

            Ok(result)
        }
        Err(e) => Ok(CreateAdminAccountResult {
            success: false,
            account_dn: None,
            sam_account_name,
            groups_added: Vec::new(),
            warnings: Vec::new(),
            error: Some(format!("Failed to create account: {}", e)),
        }),
    }
}

/// Group membership information
#[derive(serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GroupMembership {
    pub group_name: String,
    pub group_dn: String,
    pub tier: Option<String>,
    pub group_type: String,
}

/// Get group memberships for an AD object
#[tauri::command]
pub async fn get_object_groups(object_dn: String) -> Result<Vec<GroupMembership>, String> {
    use crate::infrastructure::get_object_group_memberships;

    get_object_group_memberships(&object_dn).map_err(|e| format!("Failed to get groups: {}", e))
}
