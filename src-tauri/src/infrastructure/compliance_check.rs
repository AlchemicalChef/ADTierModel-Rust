//! Compliance checking for AD Tier Model
//!
//! Detects violations of tier separation and other compliance issues.

use crate::domain::{
    ComplianceStatus, ComplianceViolation, CrossTierAccess, Tier, ViolationSeverity, ViolationType,
};

#[cfg(windows)]
use crate::infrastructure::ad_connection::AdConnection;

#[cfg(windows)]
use crate::infrastructure::ad_search::{ldap_search, SearchScope};

/// Get the domain DN for compliance checks
#[cfg(windows)]
pub fn get_domain_dn() -> Result<String, String> {
    let conn = AdConnection::connect().map_err(|e| format!("Failed to connect to AD: {:?}", e))?;
    Ok(conn.domain_dn.clone())
}

/// Check for cross-tier access violations
/// Returns accounts that have membership in groups across multiple tiers
#[cfg(windows)]
pub fn check_cross_tier_access(domain_dn: &str) -> Result<Vec<CrossTierAccess>, String> {
    use std::collections::{HashMap, HashSet};

    let mut violations = Vec::new();

    // Map to track which users are in which tier groups
    let mut user_tier_map: HashMap<String, HashSet<Tier>> = HashMap::new();
    let mut user_groups_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut user_dn_map: HashMap<String, String> = HashMap::new();

    // Check each tier's groups
    for tier in &[Tier::Tier0, Tier::Tier1, Tier::Tier2] {
        let groups_ou = format!("OU=Groups,{},{}", tier.ou_path(), domain_dn);

        // Get all groups in this tier
        let group_results = ldap_search(
            &groups_ou,
            "(objectClass=group)",
            &["name", "distinguishedName", "member"],
            SearchScope::OneLevel,
        ).unwrap_or_default();

        for group_result in group_results {
            let group_name = group_result.get("name").cloned().unwrap_or_default();

            // Get members of this group
            if let Some(members) = group_result.get_all("member") {
                for member_dn in members {
                    // Look up the member to get their sAMAccountName
                    if let Ok(member_results) = ldap_search(
                        member_dn,
                        "(objectClass=*)",
                        &["sAMAccountName", "distinguishedName", "objectClass"],
                        SearchScope::Base,
                    ) {
                        if let Some(member) = member_results.first() {
                            // Only track users, not nested groups
                            let obj_classes = member.get_all("objectclass")
                                .map(|c| c.iter().map(|s| s.to_lowercase()).collect::<Vec<_>>())
                                .unwrap_or_default();

                            if obj_classes.contains(&"user".to_string()) {
                                let sam = member.get("samaccountname").cloned().unwrap_or_default();
                                if !sam.is_empty() {
                                    user_tier_map
                                        .entry(sam.clone())
                                        .or_default()
                                        .insert(*tier);
                                    user_groups_map
                                        .entry(sam.clone())
                                        .or_default()
                                        .push(group_name.clone());
                                    user_dn_map
                                        .entry(sam)
                                        .or_insert_with(|| member_dn.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Find users with access to multiple tiers
    for (account_name, tiers) in user_tier_map {
        if tiers.len() > 1 {
            let mut tier_vec: Vec<Tier> = tiers.into_iter().collect();
            tier_vec.sort_by_key(|t| match t {
                Tier::Tier0 => 0,
                Tier::Tier1 => 1,
                Tier::Tier2 => 2,
            });

            violations.push(CrossTierAccess {
                account_name: account_name.clone(),
                account_dn: user_dn_map.get(&account_name).cloned().unwrap_or_default(),
                tiers: tier_vec,
                groups: user_groups_map.get(&account_name).cloned().unwrap_or_default(),
            });
        }
    }

    Ok(violations)
}

/// Check for stale accounts (not logged in for extended period)
#[cfg(windows)]
pub fn check_stale_accounts(domain_dn: &str, days_threshold: i64) -> Result<Vec<ComplianceViolation>, String> {
    let mut violations = Vec::new();

    // Calculate the threshold timestamp in Windows FILETIME format
    let now = chrono::Utc::now();
    let threshold_date = now - chrono::Duration::days(days_threshold);

    // Convert to Windows FILETIME (100-nanosecond intervals since January 1, 1601)
    const FILETIME_UNIX_DIFF: i64 = 11644473600;
    let threshold_filetime = (threshold_date.timestamp() + FILETIME_UNIX_DIFF) * 10_000_000;

    // Search for each tier
    for tier in &[Tier::Tier0, Tier::Tier1, Tier::Tier2] {
        let tier_dn = format!("{},{}", tier.ou_path(), domain_dn);

        // Search for enabled user accounts with old lastLogonTimestamp
        let filter = format!(
            "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<={}))",
            threshold_filetime
        );

        let results = ldap_search(
            &tier_dn,
            &filter,
            &["name", "sAMAccountName", "distinguishedName", "lastLogonTimestamp", "description"],
            SearchScope::Subtree,
        ).unwrap_or_default();

        for result in results {
            let name = result.get("name").cloned().unwrap_or_default();
            let sam = result.get("samaccountname").cloned().unwrap_or_default();
            let dn = result.get("distinguishedname").cloned().unwrap_or_default();
            let last_logon = result.get("lastlogontimestamp")
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);

            // Calculate days since last logon
            let days_inactive = if last_logon > 0 {
                let logon_secs = (last_logon / 10_000_000) - FILETIME_UNIX_DIFF;
                let now_secs = now.timestamp();
                (now_secs - logon_secs) / 86400
            } else {
                999 // Never logged on
            };

            violations.push(ComplianceViolation {
                violation_type: ViolationType::StaleAccount,
                severity: if days_inactive > 180 {
                    ViolationSeverity::High
                } else {
                    ViolationSeverity::Medium
                },
                object_name: name,
                object_dn: dn,
                sam_account_name: sam,
                description: format!("Account has not logged in for {} days", days_inactive),
                tiers_involved: vec![*tier],
                remediation: "Review account necessity and disable if no longer needed. Consider moving to a disabled accounts OU.".to_string(),
            });
        }
    }

    Ok(violations)
}

/// Check for service accounts with interactive logon capability
#[cfg(windows)]
pub fn check_service_account_logon(domain_dn: &str) -> Result<Vec<ComplianceViolation>, String> {
    let mut violations = Vec::new();

    // Search for service accounts in ServiceAccounts OUs
    for tier in &[Tier::Tier0, Tier::Tier1, Tier::Tier2] {
        let svc_ou = format!("OU=ServiceAccounts,{},{}", tier.ou_path(), domain_dn);

        // Search for enabled service accounts
        // Service accounts that can log on interactively typically:
        // 1. Don't have "Deny log on locally" applied (we can't check GPO directly)
        // 2. Are not marked as "Account is sensitive and cannot be delegated"
        // 3. Have normal user privileges (not machine accounts)
        let filter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";

        let results = ldap_search(
            &svc_ou,
            filter,
            &["name", "sAMAccountName", "distinguishedName", "userAccountControl", "description"],
            SearchScope::OneLevel,
        ).unwrap_or_default();

        for result in results {
            let name = result.get("name").cloned().unwrap_or_default();
            let sam = result.get("samaccountname").cloned().unwrap_or_default();
            let dn = result.get("distinguishedname").cloned().unwrap_or_default();
            let uac: u32 = result.get("useraccountcontrol")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            // Check for flags that indicate potential interactive logon
            // NOT_DELEGATED (0x100000) = account is sensitive
            let is_sensitive = (uac & 0x100000) != 0;

            // If not marked as sensitive, it could be used for interactive logon
            if !is_sensitive {
                violations.push(ComplianceViolation {
                    violation_type: ViolationType::ServiceAccountInteractiveLogon,
                    severity: ViolationSeverity::High,
                    object_name: name,
                    object_dn: dn,
                    sam_account_name: sam,
                    description: "Service account is not marked as sensitive and may be capable of interactive logon".to_string(),
                    tiers_involved: vec![*tier],
                    remediation: "Apply 'Deny log on locally' and 'Deny log on through Remote Desktop Services' via GPO. Mark account as 'Account is sensitive and cannot be delegated'.".to_string(),
                });
            }
        }
    }

    Ok(violations)
}

/// Check objects in wrong tier OUs based on group membership
#[cfg(windows)]
pub fn check_wrong_tier_placement(domain_dn: &str) -> Result<Vec<ComplianceViolation>, String> {
    let mut violations = Vec::new();

    // For each tier, check if objects have group memberships in other tiers
    for tier in &[Tier::Tier0, Tier::Tier1, Tier::Tier2] {
        let tier_dn = format!("{},{}", tier.ou_path(), domain_dn);

        // Get all computers in this tier
        let computer_results = ldap_search(
            &tier_dn,
            "(objectClass=computer)",
            &["name", "sAMAccountName", "distinguishedName", "memberOf"],
            SearchScope::Subtree,
        ).unwrap_or_default();

        for result in computer_results {
            let name = result.get("name").cloned().unwrap_or_default();
            let sam = result.get("samaccountname").cloned().unwrap_or_default();
            let dn = result.get("distinguishedname").cloned().unwrap_or_default();

            if let Some(memberships) = result.get_all("memberof") {
                // Check if any group membership suggests a different tier
                for group_dn in memberships {
                    let group_dn_lower = group_dn.to_lowercase();

                    // Detect wrong tier based on group location
                    let implied_tier = if group_dn_lower.contains("ou=tier0") {
                        Some(Tier::Tier0)
                    } else if group_dn_lower.contains("ou=tier1") {
                        Some(Tier::Tier1)
                    } else if group_dn_lower.contains("ou=tier2") {
                        Some(Tier::Tier2)
                    } else {
                        None
                    };

                    if let Some(implied) = implied_tier {
                        if &implied != tier {
                            // Object is in one tier but has group membership in another
                            violations.push(ComplianceViolation {
                                violation_type: ViolationType::WrongTierPlacement,
                                severity: if *tier == Tier::Tier0 || implied == Tier::Tier0 {
                                    ViolationSeverity::Critical
                                } else {
                                    ViolationSeverity::Medium
                                },
                                object_name: name.clone(),
                                object_dn: dn.clone(),
                                sam_account_name: sam.clone(),
                                description: format!(
                                    "Object is in {:?} but has group membership in {:?} group: {}",
                                    tier, implied, group_dn
                                ),
                                tiers_involved: vec![*tier, implied],
                                remediation: format!(
                                    "Either move the object to {:?} or remove it from the {:?} group",
                                    implied, implied
                                ),
                            });
                            break; // One violation per object is enough
                        }
                    }
                }
            }
        }

        // Also check users
        let user_results = ldap_search(
            &tier_dn,
            "(&(objectCategory=person)(objectClass=user))",
            &["name", "sAMAccountName", "distinguishedName", "memberOf"],
            SearchScope::Subtree,
        ).unwrap_or_default();

        for result in user_results {
            let name = result.get("name").cloned().unwrap_or_default();
            let sam = result.get("samaccountname").cloned().unwrap_or_default();
            let dn = result.get("distinguishedname").cloned().unwrap_or_default();

            if let Some(memberships) = result.get_all("memberof") {
                for group_dn in memberships {
                    let group_dn_lower = group_dn.to_lowercase();

                    let implied_tier = if group_dn_lower.contains("ou=tier0") {
                        Some(Tier::Tier0)
                    } else if group_dn_lower.contains("ou=tier1") {
                        Some(Tier::Tier1)
                    } else if group_dn_lower.contains("ou=tier2") {
                        Some(Tier::Tier2)
                    } else {
                        None
                    };

                    if let Some(implied) = implied_tier {
                        if &implied != tier {
                            violations.push(ComplianceViolation {
                                violation_type: ViolationType::WrongTierPlacement,
                                severity: if *tier == Tier::Tier0 || implied == Tier::Tier0 {
                                    ViolationSeverity::Critical
                                } else {
                                    ViolationSeverity::Medium
                                },
                                object_name: name.clone(),
                                object_dn: dn.clone(),
                                sam_account_name: sam.clone(),
                                description: format!(
                                    "User is in {:?} but has group membership in {:?} group: {}",
                                    tier, implied, group_dn
                                ),
                                tiers_involved: vec![*tier, implied],
                                remediation: format!(
                                    "Either move the user to {:?} or remove from the {:?} group",
                                    implied, implied
                                ),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(violations)
}

/// Get full compliance status
pub fn get_compliance_status(domain_dn: &str) -> Result<ComplianceStatus, String> {
    let mut status = ComplianceStatus::new();

    // Check cross-tier access
    let cross_tier = check_cross_tier_access(domain_dn)?;
    for access in &cross_tier {
        let violation = ComplianceViolation {
            violation_type: ViolationType::CrossTierAccess,
            severity: ViolationSeverity::Critical,
            object_name: access.account_name.clone(),
            object_dn: access.account_dn.clone(),
            sam_account_name: access.account_name.clone(),
            description: format!(
                "Account has access to {} tiers: {}",
                access.tiers.len(),
                access
                    .tiers
                    .iter()
                    .map(|t| format!("{:?}", t))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            tiers_involved: access.tiers.clone(),
            remediation: "Remove account from groups in all but one tier to maintain tier separation".to_string(),
        };
        status.add_violation(violation);
        status.add_cross_tier_access(access.clone());
    }

    // Check stale accounts (90 days threshold)
    let stale = check_stale_accounts(domain_dn, 90)?;
    for violation in stale {
        status.add_violation(violation);
    }

    // Check service account logon
    let svc_violations = check_service_account_logon(domain_dn)?;
    for violation in svc_violations {
        status.add_violation(violation);
    }

    // Check wrong tier placement
    let placement_violations = check_wrong_tier_placement(domain_dn)?;
    for violation in placement_violations {
        status.add_violation(violation);
    }

    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_status_scoring() {
        let mut status = ComplianceStatus::new();
        assert_eq!(status.score, 100);

        // Add a critical violation
        status.add_violation(ComplianceViolation {
            violation_type: ViolationType::CrossTierAccess,
            severity: ViolationSeverity::Critical,
            object_name: "test".to_string(),
            object_dn: "CN=test".to_string(),
            sam_account_name: "test".to_string(),
            description: "Test".to_string(),
            tiers_involved: vec![Tier::Tier0, Tier::Tier1],
            remediation: "Test".to_string(),
        });

        assert_eq!(status.score, 90); // 100 - 10 for critical
        assert_eq!(status.critical_count, 1);
    }
}
