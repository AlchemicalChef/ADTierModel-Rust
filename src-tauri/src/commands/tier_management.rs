//! Tauri commands for tier management
//!
//! These commands provide the interface between the frontend and AD operations.

use crate::domain::{
    DomainInfo, GroupSuffix, InitializationOptions, InitializationResult, InitializationStatus,
    ObjectType, SubOU, Tier, Tier0Component, Tier0RoleType, TierCounts, TierMember,
};

#[cfg(windows)]
use crate::infrastructure::{
    AdConnection, add_group_member, check_initialization_status, discover_tier0_infrastructure,
    get_tier_objects, initialize_tier_model, move_ad_object, remove_group_member,
};

#[cfg(windows)]
use std::sync::Mutex;
#[cfg(windows)]
use once_cell::sync::Lazy;

/// Cached AD connection
#[cfg(windows)]
static AD_CONNECTION: Lazy<Mutex<Option<AdConnection>>> = Lazy::new(|| Mutex::new(None));

/// Get or create AD connection
#[cfg(windows)]
fn get_connection() -> Result<std::sync::MutexGuard<'static, Option<AdConnection>>, String> {
    let mut conn = AD_CONNECTION.lock().map_err(|e| format!("Lock error: {}", e))?;

    if conn.is_none() {
        match AdConnection::connect() {
            Ok(c) => *conn = Some(c),
            Err(e) => return Err(format!("Failed to connect to AD: {}", e)),
        }
    }

    Ok(conn)
}

/// Get domain connection info
#[tauri::command]
pub async fn get_domain_info() -> Result<DomainInfo, String> {
    #[cfg(windows)]
    {
        let conn = get_connection()?;
        match conn.as_ref() {
            Some(c) => Ok(c.get_domain_info()),
            None => Err("Not connected to Active Directory".to_string()),
        }
    }

    #[cfg(not(windows))]
    {
        // Return mock data for non-Windows development
        Ok(DomainInfo {
            domain_dn: "DC=contoso,DC=com".to_string(),
            dns_root: "contoso.com".to_string(),
            netbios_name: "CONTOSO".to_string(),
            connected: false, // Indicate not actually connected
        })
    }
}

/// Get tier counts for all tiers
#[tauri::command]
pub async fn get_tier_counts() -> Result<TierCounts, String> {
    #[cfg(windows)]
    {
        let conn = get_connection()?;
        let domain_dn = match conn.as_ref() {
            Some(c) => c.domain_dn.clone(),
            None => return Err("Not connected".to_string()),
        };
        drop(conn); // Release lock before queries

        let tier0 = get_tier_objects(&domain_dn, Some(Tier::Tier0))
            .map(|v| v.len())
            .unwrap_or(0);
        let tier1 = get_tier_objects(&domain_dn, Some(Tier::Tier1))
            .map(|v| v.len())
            .unwrap_or(0);
        let tier2 = get_tier_objects(&domain_dn, Some(Tier::Tier2))
            .map(|v| v.len())
            .unwrap_or(0);
        let unassigned = get_tier_objects(&domain_dn, None)
            .map(|v| v.len())
            .unwrap_or(0);

        Ok(TierCounts {
            tier0,
            tier1,
            tier2,
            unassigned,
        })
    }

    #[cfg(not(windows))]
    {
        // Mock data for development
        Ok(TierCounts {
            tier0: 5,
            tier1: 12,
            tier2: 45,
            unassigned: 8,
        })
    }
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

    #[cfg(windows)]
    {
        let conn = get_connection()?;
        let domain_dn = match conn.as_ref() {
            Some(c) => c.domain_dn.clone(),
            None => return Err("Not connected".to_string()),
        };
        drop(conn); // Release lock before query

        get_tier_objects(&domain_dn, tier)
            .map_err(|e| format!("Query failed: {}", e))
    }

    #[cfg(not(windows))]
    {
        // Mock data for development on non-Windows
        Ok(generate_mock_members(tier))
    }
}

/// Get Tier 0 infrastructure components
#[tauri::command]
pub async fn get_tier0_infrastructure() -> Result<Vec<Tier0Component>, String> {
    #[cfg(windows)]
    {
        let conn = get_connection()?;
        let domain_dn = match conn.as_ref() {
            Some(c) => c.domain_dn.clone(),
            None => return Err("Not connected".to_string()),
        };
        drop(conn); // Release lock before query

        discover_tier0_infrastructure(&domain_dn)
            .map_err(|e| format!("Discovery failed: {}", e))
    }

    #[cfg(not(windows))]
    {
        // Mock data for development
        Ok(generate_mock_tier0_infrastructure())
    }
}

/// Force reconnection to AD
#[tauri::command]
pub async fn reconnect_ad() -> Result<DomainInfo, String> {
    #[cfg(windows)]
    {
        let mut conn = AD_CONNECTION.lock().map_err(|e| format!("Lock error: {}", e))?;
        *conn = None; // Clear existing connection

        match AdConnection::connect() {
            Ok(c) => {
                let info = c.get_domain_info();
                *conn = Some(c);
                Ok(info)
            }
            Err(e) => Err(format!("Reconnection failed: {}", e)),
        }
    }

    #[cfg(not(windows))]
    {
        Err("AD connection not available on this platform".to_string())
    }
}

// ============================================================================
// Mock data generators for non-Windows development
// ============================================================================

#[cfg(not(windows))]
fn generate_mock_members(tier: Option<Tier>) -> Vec<TierMember> {
    match tier {
        Some(Tier::Tier0) => vec![
            TierMember {
                name: "DC01".to_string(),
                sam_account_name: "DC01$".to_string(),
                object_type: ObjectType::Computer,
                tier: Some(Tier::Tier0),
                enabled: true,
                last_logon: Some("2024-11-29T10:30:00Z".to_string()),
                distinguished_name: "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com".to_string(),
                description: Some("Primary Domain Controller".to_string()),
                operating_system: Some("Windows Server 2022".to_string()),
                role_type: Some(Tier0RoleType::DomainController),
                member_count: None,
            },
            TierMember {
                name: "DC02".to_string(),
                sam_account_name: "DC02$".to_string(),
                object_type: ObjectType::Computer,
                tier: Some(Tier::Tier0),
                enabled: true,
                last_logon: Some("2024-11-29T10:25:00Z".to_string()),
                distinguished_name: "CN=DC02,OU=Domain Controllers,DC=contoso,DC=com".to_string(),
                description: Some("Secondary Domain Controller".to_string()),
                operating_system: Some("Windows Server 2022".to_string()),
                role_type: Some(Tier0RoleType::DomainController),
                member_count: None,
            },
            TierMember {
                name: "Tier0-Admins".to_string(),
                sam_account_name: "Tier0-Admins".to_string(),
                object_type: ObjectType::Group,
                tier: Some(Tier::Tier0),
                enabled: true,
                last_logon: None,
                distinguished_name: "CN=Tier0-Admins,OU=Groups,OU=Tier0,DC=contoso,DC=com".to_string(),
                description: Some("Tier 0 Administrators".to_string()),
                operating_system: None,
                role_type: None,
                member_count: Some(3),
            },
            TierMember {
                name: "admin-t0".to_string(),
                sam_account_name: "admin-t0".to_string(),
                object_type: ObjectType::User,
                tier: Some(Tier::Tier0),
                enabled: true,
                last_logon: Some("2024-11-29T08:00:00Z".to_string()),
                distinguished_name: "CN=admin-t0,OU=Users,OU=Tier0,DC=contoso,DC=com".to_string(),
                description: Some("Tier 0 Admin Account".to_string()),
                operating_system: None,
                role_type: None,
                member_count: None,
            },
            TierMember {
                name: "PAW-ADMIN01".to_string(),
                sam_account_name: "PAW-ADMIN01$".to_string(),
                object_type: ObjectType::AdminWorkstation,
                tier: Some(Tier::Tier0),
                enabled: true,
                last_logon: Some("2024-11-29T09:15:00Z".to_string()),
                distinguished_name: "CN=PAW-ADMIN01,OU=AdminWorkstations,OU=Tier0,DC=contoso,DC=com".to_string(),
                description: Some("Privileged Access Workstation".to_string()),
                operating_system: Some("Windows 11 Enterprise".to_string()),
                role_type: Some(Tier0RoleType::PAW),
                member_count: None,
            },
        ],
        Some(Tier::Tier1) => vec![
            TierMember {
                name: "SQL01".to_string(),
                sam_account_name: "SQL01$".to_string(),
                object_type: ObjectType::Computer,
                tier: Some(Tier::Tier1),
                enabled: true,
                last_logon: Some("2024-11-29T10:00:00Z".to_string()),
                distinguished_name: "CN=SQL01,OU=Computers,OU=Tier1,DC=contoso,DC=com".to_string(),
                description: Some("SQL Server".to_string()),
                operating_system: Some("Windows Server 2019".to_string()),
                role_type: None,
                member_count: None,
            },
            TierMember {
                name: "APP01".to_string(),
                sam_account_name: "APP01$".to_string(),
                object_type: ObjectType::Computer,
                tier: Some(Tier::Tier1),
                enabled: true,
                last_logon: Some("2024-11-29T09:45:00Z".to_string()),
                distinguished_name: "CN=APP01,OU=Computers,OU=Tier1,DC=contoso,DC=com".to_string(),
                description: Some("Application Server".to_string()),
                operating_system: Some("Windows Server 2019".to_string()),
                role_type: None,
                member_count: None,
            },
            TierMember {
                name: "FILE01".to_string(),
                sam_account_name: "FILE01$".to_string(),
                object_type: ObjectType::Computer,
                tier: Some(Tier::Tier1),
                enabled: true,
                last_logon: Some("2024-11-29T10:10:00Z".to_string()),
                distinguished_name: "CN=FILE01,OU=Computers,OU=Tier1,DC=contoso,DC=com".to_string(),
                description: Some("File Server".to_string()),
                operating_system: Some("Windows Server 2022".to_string()),
                role_type: None,
                member_count: None,
            },
            TierMember {
                name: "Tier1-Admins".to_string(),
                sam_account_name: "Tier1-Admins".to_string(),
                object_type: ObjectType::Group,
                tier: Some(Tier::Tier1),
                enabled: true,
                last_logon: None,
                distinguished_name: "CN=Tier1-Admins,OU=Groups,OU=Tier1,DC=contoso,DC=com".to_string(),
                description: Some("Tier 1 Administrators".to_string()),
                operating_system: None,
                role_type: None,
                member_count: Some(5),
            },
            TierMember {
                name: "svc-sql".to_string(),
                sam_account_name: "svc-sql".to_string(),
                object_type: ObjectType::ServiceAccount,
                tier: Some(Tier::Tier1),
                enabled: true,
                last_logon: Some("2024-11-29T06:00:00Z".to_string()),
                distinguished_name: "CN=svc-sql,OU=ServiceAccounts,OU=Tier1,DC=contoso,DC=com".to_string(),
                description: Some("SQL Service Account".to_string()),
                operating_system: None,
                role_type: None,
                member_count: None,
            },
        ],
        Some(Tier::Tier2) => vec![
            TierMember {
                name: "WKS001".to_string(),
                sam_account_name: "WKS001$".to_string(),
                object_type: ObjectType::Computer,
                tier: Some(Tier::Tier2),
                enabled: true,
                last_logon: Some("2024-11-29T08:30:00Z".to_string()),
                distinguished_name: "CN=WKS001,OU=Computers,OU=Tier2,DC=contoso,DC=com".to_string(),
                description: Some("User Workstation".to_string()),
                operating_system: Some("Windows 11 Pro".to_string()),
                role_type: None,
                member_count: None,
            },
            TierMember {
                name: "WKS002".to_string(),
                sam_account_name: "WKS002$".to_string(),
                object_type: ObjectType::Computer,
                tier: Some(Tier::Tier2),
                enabled: true,
                last_logon: Some("2024-11-29T09:00:00Z".to_string()),
                distinguished_name: "CN=WKS002,OU=Computers,OU=Tier2,DC=contoso,DC=com".to_string(),
                description: Some("User Workstation".to_string()),
                operating_system: Some("Windows 11 Pro".to_string()),
                role_type: None,
                member_count: None,
            },
            TierMember {
                name: "Tier2-Admins".to_string(),
                sam_account_name: "Tier2-Admins".to_string(),
                object_type: ObjectType::Group,
                tier: Some(Tier::Tier2),
                enabled: true,
                last_logon: None,
                distinguished_name: "CN=Tier2-Admins,OU=Groups,OU=Tier2,DC=contoso,DC=com".to_string(),
                description: Some("Tier 2 Administrators".to_string()),
                operating_system: None,
                role_type: None,
                member_count: Some(8),
            },
            TierMember {
                name: "helpdesk".to_string(),
                sam_account_name: "helpdesk".to_string(),
                object_type: ObjectType::User,
                tier: Some(Tier::Tier2),
                enabled: true,
                last_logon: Some("2024-11-29T07:45:00Z".to_string()),
                distinguished_name: "CN=helpdesk,OU=Users,OU=Tier2,DC=contoso,DC=com".to_string(),
                description: Some("Helpdesk Admin".to_string()),
                operating_system: None,
                role_type: None,
                member_count: None,
            },
        ],
        None => vec![
            // Unassigned objects
            TierMember {
                name: "LEGACY-SRV01".to_string(),
                sam_account_name: "LEGACY-SRV01$".to_string(),
                object_type: ObjectType::Computer,
                tier: None,
                enabled: true,
                last_logon: Some("2024-11-28T12:00:00Z".to_string()),
                distinguished_name: "CN=LEGACY-SRV01,OU=Servers,DC=contoso,DC=com".to_string(),
                description: Some("Legacy Server".to_string()),
                operating_system: Some("Windows Server 2012 R2".to_string()),
                role_type: None,
                member_count: None,
            },
            TierMember {
                name: "test-user".to_string(),
                sam_account_name: "test-user".to_string(),
                object_type: ObjectType::User,
                tier: None,
                enabled: false,
                last_logon: Some("2024-10-15T09:00:00Z".to_string()),
                distinguished_name: "CN=test-user,OU=Users,DC=contoso,DC=com".to_string(),
                description: Some("Test User Account".to_string()),
                operating_system: None,
                role_type: None,
                member_count: None,
            },
            TierMember {
                name: "OLD-WKS".to_string(),
                sam_account_name: "OLD-WKS$".to_string(),
                object_type: ObjectType::Computer,
                tier: None,
                enabled: false,
                last_logon: Some("2024-06-01T08:00:00Z".to_string()),
                distinguished_name: "CN=OLD-WKS,OU=Computers,DC=contoso,DC=com".to_string(),
                description: Some("Old Workstation".to_string()),
                operating_system: Some("Windows 10 Pro".to_string()),
                role_type: None,
                member_count: None,
            },
        ],
    }
}

#[cfg(not(windows))]
fn generate_mock_tier0_infrastructure() -> Vec<Tier0Component> {
    vec![
        // FSMO Role Holders
        Tier0Component {
            name: "DC01 (Schema Master)".to_string(),
            role_type: Tier0RoleType::SchemaMaster,
            operating_system: Some("Windows Server 2022".to_string()),
            last_logon: Some("2024-11-29T10:30:00Z".to_string()),
            current_ou: "OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            is_in_tier0: true,
            distinguished_name: "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            description: Some("FSMO Role: Schema Master".to_string()),
        },
        Tier0Component {
            name: "DC01 (Domain Naming Master)".to_string(),
            role_type: Tier0RoleType::DomainNamingMaster,
            operating_system: Some("Windows Server 2022".to_string()),
            last_logon: Some("2024-11-29T10:30:00Z".to_string()),
            current_ou: "OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            is_in_tier0: true,
            distinguished_name: "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            description: Some("FSMO Role: Domain Naming Master".to_string()),
        },
        Tier0Component {
            name: "DC01 (PDC Emulator)".to_string(),
            role_type: Tier0RoleType::PDCEmulator,
            operating_system: Some("Windows Server 2022".to_string()),
            last_logon: Some("2024-11-29T10:30:00Z".to_string()),
            current_ou: "OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            is_in_tier0: true,
            distinguished_name: "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            description: Some("FSMO Role: PDC Emulator".to_string()),
        },
        Tier0Component {
            name: "DC01 (RID Master)".to_string(),
            role_type: Tier0RoleType::RIDMaster,
            operating_system: Some("Windows Server 2022".to_string()),
            last_logon: Some("2024-11-29T10:30:00Z".to_string()),
            current_ou: "OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            is_in_tier0: true,
            distinguished_name: "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            description: Some("FSMO Role: RID Master".to_string()),
        },
        Tier0Component {
            name: "DC01 (Infrastructure Master)".to_string(),
            role_type: Tier0RoleType::InfrastructureMaster,
            operating_system: Some("Windows Server 2022".to_string()),
            last_logon: Some("2024-11-29T10:30:00Z".to_string()),
            current_ou: "OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            is_in_tier0: true,
            distinguished_name: "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            description: Some("FSMO Role: Infrastructure Master".to_string()),
        },
        // Domain Controllers
        Tier0Component {
            name: "DC01".to_string(),
            role_type: Tier0RoleType::DomainController,
            operating_system: Some("Windows Server 2022".to_string()),
            last_logon: Some("2024-11-29T10:30:00Z".to_string()),
            current_ou: "OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            is_in_tier0: true,
            distinguished_name: "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            description: Some("Primary Domain Controller".to_string()),
        },
        Tier0Component {
            name: "DC02".to_string(),
            role_type: Tier0RoleType::DomainController,
            operating_system: Some("Windows Server 2022".to_string()),
            last_logon: Some("2024-11-29T10:25:00Z".to_string()),
            current_ou: "OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            is_in_tier0: true,
            distinguished_name: "CN=DC02,OU=Domain Controllers,DC=contoso,DC=com".to_string(),
            description: Some("Secondary Domain Controller".to_string()),
        },
        // Other Tier 0 Infrastructure
        Tier0Component {
            name: "ADFS01".to_string(),
            role_type: Tier0RoleType::ADFS,
            operating_system: Some("Windows Server 2019".to_string()),
            last_logon: Some("2024-11-29T09:00:00Z".to_string()),
            current_ou: "OU=Servers,DC=contoso,DC=com".to_string(),
            is_in_tier0: false,
            distinguished_name: "CN=ADFS01,OU=Servers,DC=contoso,DC=com".to_string(),
            description: Some("AD FS Server".to_string()),
        },
        Tier0Component {
            name: "AADConnect01".to_string(),
            role_type: Tier0RoleType::EntraConnect,
            operating_system: Some("Windows Server 2019".to_string()),
            last_logon: Some("2024-11-29T08:45:00Z".to_string()),
            current_ou: "OU=Computers,OU=Tier0,DC=contoso,DC=com".to_string(),
            is_in_tier0: true,
            distinguished_name: "CN=AADConnect01,OU=Computers,OU=Tier0,DC=contoso,DC=com".to_string(),
            description: Some("Azure AD Connect Server".to_string()),
        },
        Tier0Component {
            name: "CA01".to_string(),
            role_type: Tier0RoleType::CertificateAuthority,
            operating_system: Some("Windows Server 2019".to_string()),
            last_logon: Some("2024-11-28T14:00:00Z".to_string()),
            current_ou: "OU=Servers,DC=contoso,DC=com".to_string(),
            is_in_tier0: false,
            distinguished_name: "CN=CA01,OU=Servers,DC=contoso,DC=com".to_string(),
            description: Some("Enterprise Root CA".to_string()),
        },
    ]
}

// ============================================================================
// Initialization Commands
// ============================================================================

/// Check if the tier model has been initialized
#[tauri::command]
pub async fn check_tier_initialization() -> Result<InitializationStatus, String> {
    #[cfg(windows)]
    {
        let conn = get_connection()?;
        let domain_dn = match conn.as_ref() {
            Some(c) => c.domain_dn.clone(),
            None => return Err("Not connected".to_string()),
        };
        drop(conn);

        check_initialization_status(&domain_dn).map_err(|e| format!("Check failed: {}", e))
    }

    #[cfg(not(windows))]
    {
        // Mock data for development - simulate not initialized
        Ok(InitializationStatus {
            is_initialized: false,
            tier0_ou_exists: false,
            tier1_ou_exists: false,
            tier2_ou_exists: false,
            groups_exist: false,
            missing_components: vec![
                "Tier0 OU".to_string(),
                "Tier1 OU".to_string(),
                "Tier2 OU".to_string(),
                "Tier security groups".to_string(),
            ],
        })
    }
}

/// Initialize the AD Tier Model structure
#[tauri::command]
pub async fn initialize_ad_tier_model(
    options: InitializationOptions,
) -> Result<InitializationResult, String> {
    #[cfg(windows)]
    {
        let conn = get_connection()?;
        let domain_dn = match conn.as_ref() {
            Some(c) => c.domain_dn.clone(),
            None => return Err("Not connected".to_string()),
        };
        drop(conn);

        initialize_tier_model(&domain_dn, &options).map_err(|e| format!("Initialization failed: {}", e))
    }

    #[cfg(not(windows))]
    {
        // Mock implementation for development
        let mut result = InitializationResult::new();

        if options.create_ou_structure {
            for tier in Tier::all() {
                result
                    .ous_created
                    .push(format!("OU={},DC=contoso,DC=com", tier));
                for sub_ou in SubOU::all() {
                    result.ous_created.push(format!(
                        "OU={},OU={},DC=contoso,DC=com",
                        sub_ou.as_str(),
                        tier
                    ));
                }
            }
        }

        if options.create_groups {
            for tier in Tier::all() {
                for suffix in GroupSuffix::all() {
                    result.groups_created.push(format!(
                        "CN={}-{},OU=Groups,OU={},DC=contoso,DC=com",
                        tier,
                        suffix.as_str(),
                        tier
                    ));
                }
            }
        }

        if options.set_permissions {
            result.add_warning("Permission setting is not yet implemented".to_string());
        }

        if options.create_gpos {
            result.add_warning("GPO creation is not yet implemented".to_string());
        }

        Ok(result)
    }
}

/// Get the expected OU structure that will be created
#[tauri::command]
pub async fn get_expected_ou_structure() -> Result<Vec<String>, String> {
    #[cfg(windows)]
    let domain_dn = {
        let conn = get_connection()?;
        match conn.as_ref() {
            Some(c) => c.domain_dn.clone(),
            None => return Err("Not connected".to_string()),
        }
    };

    #[cfg(not(windows))]
    let domain_dn = "DC=contoso,DC=com".to_string();

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
    let tier = match target_tier.as_str() {
        "Tier0" => Tier::Tier0,
        "Tier1" => Tier::Tier1,
        "Tier2" => Tier::Tier2,
        _ => return Err(format!("Invalid tier: {}", target_tier)),
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

    #[cfg(windows)]
    {
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

        move_ad_object(&object_dn, &target_ou)
            .map_err(|e| format!("Move failed: {}", e))
    }

    #[cfg(not(windows))]
    {
        // Mock implementation for development
        let rdn = object_dn.split(',').next().unwrap_or(&object_dn);
        let target_ou = if let Some(sub_ou) = sub {
            format!("OU={},OU={},DC=contoso,DC=com", sub_ou.as_str(), tier)
        } else {
            format!("OU={},DC=contoso,DC=com", tier)
        };
        Ok(format!("{},{}", rdn, target_ou))
    }
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

    #[cfg(windows)]
    {
        let conn = get_connection()?;
        let domain_dn = match conn.as_ref() {
            Some(c) => c.domain_dn.clone(),
            None => return Err("Not connected".to_string()),
        };
        drop(conn);

        let group_dn = crate::domain::tier_group_dn(tier, suffix, &domain_dn);

        add_group_member(&group_dn, &member_dn)
            .map_err(|e| format!("Failed to add member: {}", e))
    }

    #[cfg(not(windows))]
    {
        // Mock implementation for development
        let _ = (tier, suffix, member_dn);
        Ok(())
    }
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

    #[cfg(windows)]
    {
        let conn = get_connection()?;
        let domain_dn = match conn.as_ref() {
            Some(c) => c.domain_dn.clone(),
            None => return Err("Not connected".to_string()),
        };
        drop(conn);

        let group_dn = crate::domain::tier_group_dn(tier, suffix, &domain_dn);

        remove_group_member(&group_dn, &member_dn)
            .map_err(|e| format!("Failed to remove member: {}", e))
    }

    #[cfg(not(windows))]
    {
        // Mock implementation for development
        let _ = (tier, suffix, member_dn);
        Ok(())
    }
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

    #[cfg(windows)]
    {
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

    #[cfg(not(windows))]
    {
        // Mock implementation
        let rdn = object_dn.split(',').next().unwrap_or(&object_dn);
        Ok(format!("{},OU={},OU=Tier0,DC=contoso,DC=com", rdn, sub_ou.as_str()))
    }
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
    let tier = match options.target_tier.as_str() {
        "Tier0" => Tier::Tier0,
        "Tier1" => Tier::Tier1,
        "Tier2" => Tier::Tier2,
        _ => return Err(format!("Invalid tier: {}", options.target_tier)),
    };

    // Generate the SAM account name with tier prefix
    let sam_account_name = match options.account_type.as_str() {
        "admin" => format!("adm-t{}-{}", tier.to_string().chars().last().unwrap(), options.base_username),
        "service" => format!("svc-t{}-{}", tier.to_string().chars().last().unwrap(), options.base_username),
        _ => return Err(format!("Invalid account type: {}. Use 'admin' or 'service'", options.account_type)),
    };

    #[cfg(windows)]
    {
        use crate::infrastructure::create_admin_user;

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

    #[cfg(not(windows))]
    {
        // Mock implementation for development
        let sub_ou = match options.account_type.as_str() {
            "admin" => SubOU::Users,
            "service" => SubOU::ServiceAccounts,
            _ => SubOU::Users,
        };

        let account_dn = format!(
            "CN={},OU={},OU={},DC=contoso,DC=com",
            options.display_name,
            sub_ou.as_str(),
            tier
        );

        let groups_added: Vec<String> = options
            .groups
            .iter()
            .map(|g| format!("{}-{}", tier, g))
            .collect();

        Ok(CreateAdminAccountResult {
            success: true,
            account_dn: Some(account_dn),
            sam_account_name,
            groups_added,
            warnings: Vec::new(),
            error: None,
        })
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
    #[cfg(windows)]
    {
        use crate::infrastructure::get_object_group_memberships;

        get_object_group_memberships(&object_dn).map_err(|e| format!("Failed to get groups: {}", e))
    }

    #[cfg(not(windows))]
    {
        // Mock data for development
        let _ = object_dn;

        // Generate mock group memberships
        Ok(vec![
            GroupMembership {
                group_name: "Tier1-Admins".to_string(),
                group_dn: "CN=Tier1-Admins,OU=Groups,OU=Tier1,DC=contoso,DC=com".to_string(),
                tier: Some("Tier1".to_string()),
                group_type: "Tier Admin Group".to_string(),
            },
            GroupMembership {
                group_name: "Domain Users".to_string(),
                group_dn: "CN=Domain Users,CN=Users,DC=contoso,DC=com".to_string(),
                tier: None,
                group_type: "Built-in Group".to_string(),
            },
            GroupMembership {
                group_name: "Server Operators".to_string(),
                group_dn: "CN=Server Operators,CN=Builtin,DC=contoso,DC=com".to_string(),
                tier: None,
                group_type: "Built-in Group".to_string(),
            },
            GroupMembership {
                group_name: "Tier1-Operators".to_string(),
                group_dn: "CN=Tier1-Operators,OU=Groups,OU=Tier1,DC=contoso,DC=com".to_string(),
                tier: Some("Tier1".to_string()),
                group_type: "Tier Operator Group".to_string(),
            },
        ])
    }
}
