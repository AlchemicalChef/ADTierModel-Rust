//! Compliance checking for AD Tier Model
//!
//! Detects violations of tier separation and other compliance issues.
//! Also provides guard functions to prevent violations during write operations.

use crate::domain::{
    ComplianceStatus, ComplianceViolation, CrossTierAccess, GroupSuffix, Tier, ViolationSeverity, ViolationType,
};
use crate::infrastructure::ad_connection::AdConnection;
use crate::infrastructure::ad_search::{ldap_search, SearchScope, escape_ldap_filter, LDAP_MATCHING_RULE_IN_CHAIN};
use std::collections::HashSet;

/// Get the domain DN for compliance checks

pub fn get_domain_dn() -> Result<String, String> {
    let conn = AdConnection::connect().map_err(|e| format!("Failed to connect to AD: {:?}", e))?;
    Ok(conn.domain_dn.clone())
}

// ============================================================================
// TLA+ GUARD FUNCTIONS - Enforce invariants during write operations
// These functions implement the guards specified in the TLA+ model to prevent
// tier isolation violations rather than just detecting them after the fact.
// ============================================================================

/// Get the admin tiers that a member currently has access to.
/// This is used as a guard before adding members to admin groups.
///
/// Implements TLA+ function: AdminTiers(obj) from ADTierModel.tla lines 166-167
/// Uses LDAP_MATCHING_RULE_IN_CHAIN for transitive group membership checking.
///
/// # Arguments
/// * `member_dn` - Distinguished name of the member to check
/// * `domain_dn` - Domain distinguished name for LDAP searches
///
/// # Returns
/// * `Ok(HashSet<Tier>)` - Set of tiers where the member has admin group membership
/// * `Err(String)` - Error message if the check fails
pub fn get_member_admin_tiers(member_dn: &str, domain_dn: &str) -> Result<HashSet<Tier>, String> {
    let mut admin_tiers: HashSet<Tier> = HashSet::new();

    // Check each tier's admin groups (Admins and Operators grant admin privileges)
    for tier in &[Tier::Tier0, Tier::Tier1, Tier::Tier2] {
        let groups_ou = format!("OU=Groups,{},{}", tier.ou_path(), domain_dn);

        // Get admin groups (Admins and Operators) in this tier
        for suffix in &[GroupSuffix::Admins, GroupSuffix::Operators] {
            let group_name = format!("{}-{}", tier, suffix.as_str());

            // Find the group DN
            let group_filter = format!(
                "(&(objectClass=group)(sAMAccountName={}))",
                escape_ldap_filter(&group_name)
            );

            let group_results = ldap_search(
                &groups_ou,
                &group_filter,
                &["distinguishedName"],
                SearchScope::OneLevel,
            ).unwrap_or_default();

            if let Some(group_result) = group_results.first() {
                if let Some(group_dn) = group_result.get("distinguishedname") {
                    // Check if member is in this group using LDAP_MATCHING_RULE_IN_CHAIN
                    // This catches both direct and nested membership
                    let member_filter = format!(
                        "(&(distinguishedName={})(memberOf:{}:={}))",
                        escape_ldap_filter(member_dn),
                        LDAP_MATCHING_RULE_IN_CHAIN,
                        escape_ldap_filter(group_dn)
                    );

                    if let Ok(member_results) = ldap_search(
                        domain_dn,
                        &member_filter,
                        &["distinguishedName"],
                        SearchScope::Subtree,
                    ) {
                        if !member_results.is_empty() {
                            admin_tiers.insert(*tier);
                            tracing::debug!(
                                member_dn = member_dn,
                                group = group_name,
                                tier = ?tier,
                                "Member has admin access in tier"
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(admin_tiers)
}

/// Check if adding a member to an admin group would violate tier isolation.
/// This implements the guard from TLA+ AddToTierGroup action (lines 440-448).
///
/// TLA+ Guard:
/// ```
/// IsAdminGroup(group) =>
///   LET currentAdminTiers == AdminTiers(obj)
///       newTier == TierOfGroup(group)
///   IN \/ currentAdminTiers = {}
///      \/ currentAdminTiers = {newTier}
/// ```
///
/// # Arguments
/// * `member_dn` - Distinguished name of the member to add
/// * `target_tier` - The tier of the group being added to
/// * `group_suffix` - The type of group (Admins, Operators, etc.)
/// * `domain_dn` - Domain distinguished name
///
/// # Returns
/// * `Ok(())` - Addition is allowed
/// * `Err(String)` - Addition would violate tier isolation
pub fn check_tier_isolation_guard(
    member_dn: &str,
    target_tier: Tier,
    group_suffix: GroupSuffix,
    domain_dn: &str,
) -> Result<(), String> {
    // Only check for admin groups (Admins and Operators grant privileged access)
    let is_admin_group = matches!(group_suffix, GroupSuffix::Admins | GroupSuffix::Operators);

    if !is_admin_group {
        // Non-admin groups (Readers, ServiceAccounts, JumpServers) don't require tier isolation
        return Ok(());
    }

    // Get current admin tiers for the member
    let current_admin_tiers = get_member_admin_tiers(member_dn, domain_dn)?;

    tracing::debug!(
        member_dn = member_dn,
        target_tier = ?target_tier,
        current_tiers = ?current_admin_tiers,
        "Checking tier isolation guard"
    );

    // TLA+ Guard: currentAdminTiers = {} \/ currentAdminTiers = {newTier}
    if current_admin_tiers.is_empty() {
        // No existing admin access - OK to add
        return Ok(());
    }

    if current_admin_tiers.len() == 1 && current_admin_tiers.contains(&target_tier) {
        // Already has admin access only in the target tier - OK to add
        return Ok(());
    }

    // Violation: member already has admin access in a different tier
    let existing_tiers: Vec<String> = current_admin_tiers
        .iter()
        .map(|t| format!("{:?}", t))
        .collect();

    Err(format!(
        "TIER ISOLATION VIOLATION: Cannot add member to {:?} admin group. \
         Member already has admin access in: {}. \
         Per TLA+ invariant INV-1 (TierIsolation), a user cannot have admin rights in multiple tiers. \
         Remove existing admin group memberships first.",
        target_tier,
        existing_tiers.join(", ")
    ))
}

/// Check if an object is a service account based on its location in the OU structure.
/// Service accounts are expected to be in the ServiceAccounts sub-OU of a tier.
pub fn is_service_account(object_dn: &str) -> bool {
    object_dn.to_lowercase().contains("ou=serviceaccounts")
}

/// Check if a service account is hardened (marked as sensitive and cannot be delegated).
/// This checks the userAccountControl flag NOT_DELEGATED (0x100000).
///
/// # Arguments
/// * `object_dn` - Distinguished name of the service account
///
/// # Returns
/// * `Ok(true)` - Account is hardened
/// * `Ok(false)` - Account is not hardened
/// * `Err(String)` - Failed to check
pub fn is_service_account_hardened(object_dn: &str) -> Result<bool, String> {
    let results = ldap_search(
        object_dn,
        "(objectClass=*)",
        &["userAccountControl"],
        SearchScope::Base,
    ).map_err(|e| format!("Failed to query service account: {:?}", e))?;

    if let Some(result) = results.first() {
        if let Some(uac_str) = result.get("useraccountcontrol") {
            let uac: u32 = uac_str.parse().unwrap_or(0);
            // NOT_DELEGATED flag = 0x100000 (1048576)
            let is_sensitive = (uac & 0x100000) != 0;
            return Ok(is_sensitive);
        }
    }

    // If we can't determine, assume not hardened for safety
    Ok(false)
}

/// Check if moving an object to a privileged tier is allowed.
/// Implements TLA+ guard from MoveObjectToTier action (lines 425-436).
///
/// TLA+ Guard:
/// ```
/// (obj \in ServiceAccounts /\ targetTier \in {"Tier0", "Tier1"}) =>
///     serviceAccountSensitive[obj] = TRUE
/// ```
///
/// # Arguments
/// * `object_dn` - Distinguished name of the object being moved
/// * `target_tier` - The tier the object is being moved to
///
/// # Returns
/// * `Ok(())` - Move is allowed
/// * `Err(String)` - Move would violate service account hardening requirement
pub fn check_service_account_hardening_guard(
    object_dn: &str,
    target_tier: Tier,
) -> Result<(), String> {
    // Only check for privileged tiers
    if !matches!(target_tier, Tier::Tier0 | Tier::Tier1) {
        return Ok(());
    }

    // Only check for service accounts
    if !is_service_account(object_dn) {
        return Ok(());
    }

    // Check if the service account is hardened
    let is_hardened = is_service_account_hardened(object_dn)?;

    if !is_hardened {
        return Err(format!(
            "SERVICE ACCOUNT HARDENING VIOLATION: Cannot move service account to {:?}. \
             Per TLA+ invariant INV-10 (ServiceAccountHardening), service accounts must be \
             marked as 'Account is sensitive and cannot be delegated' before moving to \
             privileged tiers (Tier0 or Tier1). \
             Harden the service account first using the compliance remediation tools.",
            target_tier
        ));
    }

    Ok(())
}

/// Check if an object's current group memberships are consistent with a target tier.
/// Used when moving objects to ensure they don't have conflicting admin group memberships.
///
/// Implements TLA+ invariant INV-4 (ObjectTierConsistency).
///
/// # Arguments
/// * `object_dn` - Distinguished name of the object being moved
/// * `target_tier` - The tier the object is being moved to
/// * `domain_dn` - Domain distinguished name
///
/// # Returns
/// * `Ok(Vec<String>)` - List of conflicting groups (empty if none)
/// * `Err(String)` - Failed to check
pub fn check_object_tier_consistency(
    object_dn: &str,
    target_tier: Tier,
    domain_dn: &str,
) -> Result<Vec<String>, String> {
    let mut conflicting_groups: Vec<String> = Vec::new();

    // Get current admin tiers
    let current_admin_tiers = get_member_admin_tiers(object_dn, domain_dn)?;

    // Check if any admin tier conflicts with target
    for tier in current_admin_tiers {
        if tier != target_tier {
            conflicting_groups.push(format!("{:?}-Admins or {:?}-Operators", tier, tier));
        }
    }

    Ok(conflicting_groups)
}

/// Check for cross-tier access violations
/// Returns accounts that have membership in groups across multiple tiers
///
/// Uses LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) for transitive
/// group membership checking, which catches users who are members through
/// nested groups.

pub fn check_cross_tier_access(domain_dn: &str) -> Result<Vec<CrossTierAccess>, String> {
    use std::collections::{HashMap, HashSet};
    use crate::infrastructure::ad_search::LDAP_MATCHING_RULE_IN_CHAIN;

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
            &["name", "distinguishedName"],
            SearchScope::OneLevel,
        ).unwrap_or_default();

        for group_result in group_results {
            let group_name = group_result.get("name").cloned().unwrap_or_default();
            let group_dn = match group_result.get("distinguishedname") {
                Some(dn) => dn.clone(),
                None => continue,
            };

            // Use LDAP_MATCHING_RULE_IN_CHAIN to find ALL users who are members
            // of this group, including through nested group membership
            let filter = format!(
                "(&(objectCategory=person)(objectClass=user)(memberOf:{}:={}))",
                LDAP_MATCHING_RULE_IN_CHAIN,
                escape_ldap_filter(&group_dn)
            );

            if let Ok(user_results) = ldap_search(
                domain_dn,
                &filter,
                &["sAMAccountName", "distinguishedName"],
                SearchScope::Subtree,
            ) {
                for user in user_results {
                    let sam = user.get("samaccountname").cloned().unwrap_or_default();
                    let dn = user.get("distinguishedname").cloned().unwrap_or_default();

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
                            .or_insert(dn);
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

            // Deduplicate groups list
            let mut groups = user_groups_map.get(&account_name).cloned().unwrap_or_default();
            groups.sort();
            groups.dedup();

            violations.push(CrossTierAccess {
                account_name: account_name.clone(),
                account_dn: user_dn_map.get(&account_name).cloned().unwrap_or_default(),
                tiers: tier_vec,
                groups,
            });
        }
    }

    tracing::info!(
        violation_count = violations.len(),
        "Cross-tier access check completed"
    );

    Ok(violations)
}

/// Check for stale accounts (not logged in for extended period)

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

/// Helper function to check tier placement violations for a specific object type.
/// This consolidates the duplicate logic for checking computers and users.

fn check_object_type_tier_placement(
    tier: &Tier,
    tier_dn: &str,
    ldap_filter: &str,
    object_type_label: &str,
) -> Vec<ComplianceViolation> {
    let mut violations = Vec::new();

    let results = ldap_search(
        tier_dn,
        ldap_filter,
        &["name", "sAMAccountName", "distinguishedName", "memberOf"],
        SearchScope::Subtree,
    ).unwrap_or_default();

    for result in results {
        let name = result.get("name").cloned().unwrap_or_default();
        let sam = result.get("samaccountname").cloned().unwrap_or_default();
        let dn = result.get("distinguishedname").cloned().unwrap_or_default();

        if let Some(memberships) = result.get_all("memberof") {
            // Check if any group membership suggests a different tier
            for group_dn in memberships {
                // Use proper DN parsing instead of fragile substring matching
                let implied_tier = Tier::from_dn(group_dn);

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
                                "{} is in {:?} but has group membership in {:?} group: {}",
                                object_type_label, tier, implied, group_dn
                            ),
                            tiers_involved: vec![*tier, implied],
                            remediation: format!(
                                "Either move the {} to {:?} or remove it from the {:?} group",
                                object_type_label.to_lowercase(), implied, implied
                            ),
                        });
                        break; // One violation per object is enough
                    }
                }
            }
        }
    }

    violations
}

/// Check objects in wrong tier OUs based on group membership

pub fn check_wrong_tier_placement(domain_dn: &str) -> Result<Vec<ComplianceViolation>, String> {
    let mut violations = Vec::new();

    // For each tier, check if objects have group memberships in other tiers
    for tier in &[Tier::Tier0, Tier::Tier1, Tier::Tier2] {
        let tier_dn = tier.full_ou_dn(domain_dn);

        // Check computers
        violations.extend(check_object_type_tier_placement(
            tier,
            &tier_dn,
            "(objectClass=computer)",
            "Computer",
        ));

        // Check users
        violations.extend(check_object_type_tier_placement(
            tier,
            &tier_dn,
            "(&(objectCategory=person)(objectClass=user))",
            "User",
        ));
    }

    Ok(violations)
}

/// Check for objects not assigned to any tier
/// Returns violations for unassigned computers and users which should be tiered
pub fn check_unassigned_objects(domain_dn: &str) -> Result<Vec<ComplianceViolation>, String> {
    use crate::domain::ObjectType;
    use crate::infrastructure::ad_search::get_tier_objects;

    let unassigned = get_tier_objects(domain_dn, None)
        .map_err(|e| format!("Failed to get unassigned objects: {:?}", e))?;

    let mut violations = Vec::new();

    // Count by type
    let mut computer_count = 0usize;
    let mut user_count = 0usize;
    let mut group_count = 0usize;
    let mut enabled_computers: Vec<_> = Vec::new();
    let mut enabled_users: Vec<_> = Vec::new();

    for member in &unassigned {
        match member.object_type {
            ObjectType::Computer | ObjectType::AdminWorkstation => {
                computer_count += 1;
                if member.enabled {
                    enabled_computers.push(member);
                }
            }
            ObjectType::User | ObjectType::ServiceAccount => {
                user_count += 1;
                if member.enabled {
                    enabled_users.push(member);
                }
            }
            ObjectType::Group => {
                group_count += 1;
            }
        }
    }

    let total = computer_count + user_count + group_count;

    // Only flag if there are unassigned objects
    if total > 0 {
        // Create a summary violation
        let description = format!(
            "{} unassigned objects not in any tier: {} computers, {} users, {} groups",
            total, computer_count, user_count, group_count
        );

        violations.push(ComplianceViolation {
            violation_type: ViolationType::UnassignedObject,
            severity: if enabled_computers.len() + enabled_users.len() > 100 {
                ViolationSeverity::Critical  // Many enabled unassigned objects is critical
            } else if total > 50 {
                ViolationSeverity::High
            } else {
                ViolationSeverity::Medium
            },
            object_name: format!("Unassigned Objects ({})", total),
            object_dn: domain_dn.to_string(),
            sam_account_name: "N/A".to_string(),
            description,
            tiers_involved: vec![],
            remediation: format!(
                "Assign objects to appropriate tiers. {} enabled computers and {} enabled users need immediate attention.",
                enabled_computers.len(), enabled_users.len()
            ),
        });

        // Add individual violations for enabled computers (limit to first 20 to avoid spam)
        for (i, computer) in enabled_computers.iter().take(20).enumerate() {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::UnassignedObject,
                severity: ViolationSeverity::High,
                object_name: computer.name.clone(),
                object_dn: computer.distinguished_name.clone(),
                sam_account_name: computer.sam_account_name.clone(),
                description: format!(
                    "Enabled computer not assigned to any tier{}",
                    if i == 19 && enabled_computers.len() > 20 {
                        format!(" (+{} more)", enabled_computers.len() - 20)
                    } else {
                        String::new()
                    }
                ),
                tiers_involved: vec![],
                remediation: "Move this computer to an appropriate tier OU (Tier1 for servers, Tier2 for workstations)".to_string(),
            });
        }

        // Add individual violations for enabled users (limit to first 10)
        for (i, user) in enabled_users.iter().take(10).enumerate() {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::UnassignedObject,
                severity: ViolationSeverity::High,
                object_name: user.name.clone(),
                object_dn: user.distinguished_name.clone(),
                sam_account_name: user.sam_account_name.clone(),
                description: format!(
                    "Enabled user not assigned to any tier{}",
                    if i == 9 && enabled_users.len() > 10 {
                        format!(" (+{} more)", enabled_users.len() - 10)
                    } else {
                        String::new()
                    }
                ),
                tiers_involved: vec![],
                remediation: "Assign this user to an appropriate tier based on their role and access requirements".to_string(),
            });
        }
    }

    tracing::info!(
        total = total,
        computers = computer_count,
        users = user_count,
        groups = group_count,
        enabled_computers = enabled_computers.len(),
        enabled_users = enabled_users.len(),
        "Unassigned objects check completed"
    );

    Ok(violations)
}

/// Get full compliance status
///
/// # Arguments
/// * `domain_dn` - The domain distinguished name
/// * `stale_threshold_days` - Number of days without logon to consider an account stale
pub fn get_compliance_status(domain_dn: &str, stale_threshold_days: u32) -> Result<ComplianceStatus, String> {
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

    // Check stale accounts using configurable threshold
    let stale = check_stale_accounts(domain_dn, stale_threshold_days as i64)?;
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

    // Check for unassigned objects (not in any tier)
    let unassigned_violations = check_unassigned_objects(domain_dn)?;
    for violation in unassigned_violations {
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
