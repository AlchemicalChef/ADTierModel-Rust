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

// ============================================================================
// BUILT-IN PRIVILEGED GROUPS
// These groups have domain-wide admin rights and are protected by AdminSDHolder.
// Members are implicitly Tier 0 principals regardless of OU placement.
// ============================================================================

/// Well-known built-in privileged group names (AdminSDHolder-protected)
pub const BUILTIN_PRIVILEGED_GROUPS: &[&str] = &[
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "Backup Operators",
    "Replicators",
    "Key Admins",
    "Enterprise Key Admins",
];

/// Well-known built-in privileged group RIDs
pub const BUILTIN_PRIVILEGED_RIDS: &[u32] = &[
    512,  // Domain Admins
    518,  // Schema Admins
    519,  // Enterprise Admins
    544,  // Administrators (BUILTIN)
    548,  // Account Operators
    549,  // Server Operators
    550,  // Print Operators
    551,  // Backup Operators
    552,  // Replicators
    526,  // Key Admins
    527,  // Enterprise Key Admins
];

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

// ============================================================================
// ADMINSDHOLDER DETECTION
// AdminSDHolder is a security mechanism that protects privileged accounts.
// Objects with adminCount=1 have their ACLs reset hourly by SDProp.
// ============================================================================

/// Check if an object is protected by AdminSDHolder (has adminCount=1).
///
/// AdminSDHolder protection is applied to members of protected groups. The SDProp
/// process resets the ACL of these objects every 60 minutes based on the AdminSDHolder
/// object's ACL. This is a critical security mechanism but can cause issues if
/// accounts have adminCount=1 but are no longer in protected groups (orphaned).
///
/// # Arguments
/// * `object_dn` - Distinguished name of the object to check
///
/// # Returns
/// * `Ok(Some(true))` - Object has adminCount=1 (protected)
/// * `Ok(Some(false))` - Object has adminCount=0 or not set (not protected)
/// * `Ok(None)` - Could not determine (object not found or attribute missing)
/// * `Err(String)` - Query failed
pub fn check_admin_count(object_dn: &str) -> Result<Option<bool>, String> {
    let results = ldap_search(
        object_dn,
        "(objectClass=*)",
        &["adminCount"],
        SearchScope::Base,
    ).map_err(|e| format!("Failed to query adminCount: {:?}", e))?;

    if let Some(result) = results.first() {
        if let Some(admin_count_str) = result.get("admincount") {
            let admin_count: i32 = admin_count_str.parse().unwrap_or(0);
            return Ok(Some(admin_count == 1));
        }
        // Attribute exists but is empty or not set
        return Ok(Some(false));
    }

    Ok(None)
}

/// Find all objects with adminCount=1 (AdminSDHolder-protected objects).
///
/// This is useful for security auditing to identify:
/// 1. Legitimate protected accounts (members of protected groups)
/// 2. Orphaned protected accounts (adminCount=1 but no longer in protected groups)
///
/// # Arguments
/// * `domain_dn` - Domain distinguished name
///
/// # Returns
/// * Vector of objects with adminCount=1, including their DN and sAMAccountName
pub fn find_admin_count_objects(domain_dn: &str) -> Result<Vec<std::collections::HashMap<String, String>>, String> {
    use crate::infrastructure::ad_search::SearchResult;

    // Search for all objects with adminCount=1
    let filter = "(adminCount=1)";

    let results: Vec<SearchResult> = ldap_search(
        domain_dn,
        filter,
        &["name", "sAMAccountName", "distinguishedName", "objectClass", "memberOf"],
        SearchScope::Subtree,
    ).map_err(|e| format!("Failed to find adminCount objects: {:?}", e))?;

    // Convert SearchResult to HashMap<String, String> (flatten multi-value to first value)
    let hash_maps: Vec<std::collections::HashMap<String, String>> = results
        .into_iter()
        .map(|sr| {
            sr.attributes
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().next().unwrap_or_default()))
                .collect()
        })
        .collect();

    Ok(hash_maps)
}

/// Check for AdminSDHolder compliance violations.
///
/// Detects:
/// 1. Orphaned adminCount - Objects with adminCount=1 but not in any protected group
/// 2. Protected group members in lower tiers - High-privilege accounts in Tier 1/2
///
/// # Arguments
/// * `domain_dn` - Domain distinguished name
///
/// # Returns
/// * Vector of compliance violations related to AdminSDHolder
pub fn check_admin_sdholder_violations(domain_dn: &str) -> Result<Vec<ComplianceViolation>, String> {
    let mut violations = Vec::new();

    // Find all objects with adminCount=1
    let admin_count_objects = find_admin_count_objects(domain_dn)?;

    tracing::info!(
        count = admin_count_objects.len(),
        "Found objects with adminCount=1"
    );

    for obj in admin_count_objects {
        let name = obj.get("name").cloned().unwrap_or_default();
        let sam = obj.get("samaccountname").cloned().unwrap_or_default();
        let dn = obj.get("distinguishedname").cloned().unwrap_or_default();
        let object_classes = obj.get("objectclass").cloned().unwrap_or_default();

        // Skip computer accounts (DCs and other protected computers are expected)
        if object_classes.to_lowercase().contains("computer") {
            continue;
        }

        // Check if object is in a tier OU (Tier0 is expected, Tier1/2 is a violation)
        let object_tier = Tier::from_dn(&dn);

        match object_tier {
            Some(Tier::Tier0) => {
                // Expected - protected accounts should be in Tier 0
                continue;
            }
            Some(tier) => {
                // Violation: Protected account in lower tier
                violations.push(ComplianceViolation {
                    violation_type: ViolationType::MisplacedTier0Infrastructure,
                    severity: ViolationSeverity::Critical,
                    object_name: name,
                    object_dn: dn,
                    sam_account_name: sam,
                    description: format!(
                        "AdminSDHolder-protected account (adminCount=1) found in {:?}. \
                         Protected accounts are Tier 0 principals and should not be in lower tiers.",
                        tier
                    ),
                    tiers_involved: vec![Tier::Tier0, tier],
                    remediation: "Move this account to Tier 0 or remove from protected groups and clear adminCount".to_string(),
                });
            }
            None => {
                // Object not in any tier OU - check if it's a potential orphan
                // For now, just log it; orphaned adminCount is a lesser concern
                tracing::debug!(
                    name = name,
                    dn = dn,
                    "AdminSDHolder-protected object not in tier OU"
                );
            }
        }
    }

    Ok(violations)
}

/// Check if a user is a member of any built-in privileged group.
///
/// Uses LDAP_MATCHING_RULE_IN_CHAIN for transitive membership checking.
///
/// # Arguments
/// * `user_dn` - Distinguished name of the user
/// * `domain_dn` - Domain distinguished name
///
/// # Returns
/// * Vector of built-in privileged group names the user is a member of
pub fn get_builtin_group_memberships(user_dn: &str, domain_dn: &str) -> Result<Vec<String>, String> {
    let mut memberships = Vec::new();

    for group_name in BUILTIN_PRIVILEGED_GROUPS {
        // Find the group DN
        let group_filter = format!(
            "(&(objectClass=group)(sAMAccountName={}))",
            escape_ldap_filter(group_name)
        );

        let group_results = ldap_search(
            domain_dn,
            &group_filter,
            &["distinguishedName"],
            SearchScope::Subtree,
        ).unwrap_or_default();

        if let Some(group_result) = group_results.first() {
            if let Some(group_dn) = group_result.get("distinguishedname") {
                // Check if user is member (transitively)
                let member_filter = format!(
                    "(&(distinguishedName={})(memberOf:{}:={}))",
                    escape_ldap_filter(user_dn),
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
                        memberships.push(group_name.to_string());
                    }
                }
            }
        }
    }

    Ok(memberships)
}

// ============================================================================
// KERBEROS DELEGATION ATTACK PATH DETECTION
// MITRE ATT&CK: T1558.001, T1558.003, T1558.004, T1134.002
// ============================================================================

/// userAccountControl flag for unconstrained delegation
const TRUSTED_FOR_DELEGATION: u32 = 0x80000; // 524288

/// Check for Kerberos delegation vulnerabilities that bypass tier isolation.
///
/// Detects:
/// 1. Unconstrained Delegation (TRUSTED_FOR_DELEGATION) - CRITICAL
///    Allows capture of TGTs from any authenticating user
/// 2. Constrained Delegation (msDS-AllowedToDelegateTo) - HIGH
///    Can be abused for S4U2Self/S4U2Proxy attacks
/// 3. Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity) - CRITICAL
///    Any principal with write access can configure delegation to themselves
///
/// # Arguments
/// * `domain_dn` - Domain distinguished name
///
/// # Returns
/// * Vector of compliance violations for delegation issues
pub fn check_delegation_violations(domain_dn: &str) -> Result<Vec<ComplianceViolation>, String> {
    let mut violations = Vec::new();

    // =========================================================================
    // 1. UNCONSTRAINED DELEGATION (CRITICAL)
    // Computers/users with TRUSTED_FOR_DELEGATION can capture TGTs
    // Filter excludes Domain Controllers (they have this legitimately)
    // =========================================================================
    let unconstrained_filter = format!(
        "(&(userAccountControl:1.2.840.113556.1.4.803:={})(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
        TRUSTED_FOR_DELEGATION
    );

    let unconstrained_results = ldap_search(
        domain_dn,
        &unconstrained_filter,
        &["name", "sAMAccountName", "distinguishedName", "objectClass", "userAccountControl"],
        SearchScope::Subtree,
    ).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "Failed to query unconstrained delegation");
        Vec::new()
    });

    for result in &unconstrained_results {
        let name = result.get("name").cloned().unwrap_or_default();
        let sam = result.get("samaccountname").cloned().unwrap_or_default();
        let dn = result.get("distinguishedname").cloned().unwrap_or_default();
        let object_class = result.get("objectclass").cloned().unwrap_or_default();

        // Determine object tier
        let object_tier = Tier::from_dn(&dn);

        violations.push(ComplianceViolation {
            violation_type: ViolationType::UnconstrainedDelegation,
            severity: ViolationSeverity::Critical,
            object_name: name,
            object_dn: dn,
            sam_account_name: sam,
            description: format!(
                "Unconstrained delegation enabled (TRUSTED_FOR_DELEGATION). \
                 Any user authenticating to this {} can have their TGT captured and reused.",
                if object_class.to_lowercase().contains("computer") { "computer" } else { "account" }
            ),
            tiers_involved: object_tier.map(|t| vec![t]).unwrap_or_default(),
            remediation: "Remove unconstrained delegation. Use constrained delegation with protocol transition if needed. \
                         For Tier 0, consider Protected Users group membership.".to_string(),
        });
    }

    // =========================================================================
    // 2. CONSTRAINED DELEGATION (HIGH)
    // Accounts with msDS-AllowedToDelegateTo can impersonate users to specific services
    // =========================================================================
    let constrained_filter = "(msDS-AllowedToDelegateTo=*)";

    let constrained_results = ldap_search(
        domain_dn,
        constrained_filter,
        &["name", "sAMAccountName", "distinguishedName", "msDS-AllowedToDelegateTo", "userAccountControl"],
        SearchScope::Subtree,
    ).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "Failed to query constrained delegation");
        Vec::new()
    });

    for result in &constrained_results {
        let name = result.get("name").cloned().unwrap_or_default();
        let sam = result.get("samaccountname").cloned().unwrap_or_default();
        let dn = result.get("distinguishedname").cloned().unwrap_or_default();
        let delegate_to = result.get("msds-allowedtodelegateto").cloned().unwrap_or_default();
        let uac: u32 = result.get("useraccountcontrol")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Check if protocol transition is enabled (more dangerous)
        let has_protocol_transition = (uac & 0x1000000) != 0; // TRUSTED_TO_AUTH_FOR_DELEGATION

        let object_tier = Tier::from_dn(&dn);

        // Only flag as violation if not a Domain Controller or if targeting Tier 0 services
        let is_tier0_target = delegate_to.to_lowercase().contains("dc=") ||
                              delegate_to.to_lowercase().contains("ldap/") ||
                              delegate_to.to_lowercase().contains("cifs/") && delegate_to.to_lowercase().contains("dc");

        violations.push(ComplianceViolation {
            violation_type: ViolationType::ConstrainedDelegation,
            severity: if is_tier0_target || has_protocol_transition {
                ViolationSeverity::Critical
            } else {
                ViolationSeverity::High
            },
            object_name: name,
            object_dn: dn,
            sam_account_name: sam,
            description: format!(
                "Constrained delegation to: {}{}. {}",
                delegate_to,
                if has_protocol_transition { " (with protocol transition - S4U2Self enabled)" } else { "" },
                if is_tier0_target { "TARGETS TIER 0 SERVICES!" } else { "" }
            ),
            tiers_involved: object_tier.map(|t| vec![t]).unwrap_or_default(),
            remediation: "Review delegation targets. Remove if not required. \
                         Ensure delegation targets are within the same tier.".to_string(),
        });
    }

    // =========================================================================
    // 3. RESOURCE-BASED CONSTRAINED DELEGATION (RBCD) (CRITICAL)
    // Any principal with write access to a computer can configure RBCD to themselves
    // =========================================================================
    let rbcd_filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)";

    let rbcd_results = ldap_search(
        domain_dn,
        rbcd_filter,
        &["name", "sAMAccountName", "distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity"],
        SearchScope::Subtree,
    ).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "Failed to query RBCD");
        Vec::new()
    });

    for result in &rbcd_results {
        let name = result.get("name").cloned().unwrap_or_default();
        let sam = result.get("samaccountname").cloned().unwrap_or_default();
        let dn = result.get("distinguishedname").cloned().unwrap_or_default();

        let object_tier = Tier::from_dn(&dn);
        let is_tier0 = object_tier == Some(Tier::Tier0);

        violations.push(ComplianceViolation {
            violation_type: ViolationType::ResourceBasedConstrainedDelegation,
            severity: ViolationSeverity::Critical,
            object_name: name,
            object_dn: dn,
            sam_account_name: sam,
            description: format!(
                "Resource-Based Constrained Delegation configured. \
                 {}Principals in the RBCD list can impersonate any user to services on this computer.",
                if is_tier0 { "THIS IS A TIER 0 SYSTEM! " } else { "" }
            ),
            tiers_involved: object_tier.map(|t| vec![t]).unwrap_or_default(),
            remediation: "Clear msDS-AllowedToActOnBehalfOfOtherIdentity unless explicitly required. \
                         Audit who has write access to this computer object.".to_string(),
        });
    }

    tracing::info!(
        unconstrained = unconstrained_results.len(),
        constrained = constrained_results.len(),
        rbcd = rbcd_results.len(),
        "Delegation violation check completed"
    );

    Ok(violations)
}

// ============================================================================
// ACL-BASED ATTACK PATH DETECTION (SHADOW ADMINS)
// MITRE ATT&CK: T1222.001, T1078.002
// ============================================================================

/// Dangerous ACL rights that grant effective control over AD objects
/// These map to BloodHound-style attack edges
const DANGEROUS_ACL_RIGHTS: &[&str] = &[
    "GenericAll",           // Full control
    "GenericWrite",         // Write all properties
    "WriteDacl",            // Modify ACL
    "WriteOwner",           // Take ownership
    "WriteProperty",        // Write specific properties (can include dangerous ones)
    "ExtendedRight",        // Includes ForceChangePassword, DS-Replication-Get-Changes
    "Self",                 // Validated writes (can add self to group)
];

/// Well-known Tier 0 object paths that should be protected
const TIER0_PROTECTED_OBJECTS: &[&str] = &[
    "CN=Administrators,CN=Builtin",
    "CN=Domain Admins,CN=Users",
    "CN=Enterprise Admins,CN=Users",
    "CN=Schema Admins,CN=Users",
    "CN=Domain Controllers,CN=Users",
    "CN=AdminSDHolder,CN=System",
];

/// Check for ACL-based attack paths (Shadow Admins)
///
/// Detects non-Tier0 principals with dangerous permissions on Tier 0 objects:
/// - GenericAll: Full control
/// - WriteDacl: Can modify ACL to grant themselves more access
/// - WriteOwner: Can take ownership and then modify ACL
/// - ForceChangePassword: Can reset passwords of Tier 0 accounts
///
/// This is a simplified implementation that checks for common shadow admin paths.
/// A full implementation would require parsing nTSecurityDescriptor binary data.
///
/// # Arguments
/// * `domain_dn` - Domain distinguished name
///
/// # Returns
/// * Vector of compliance violations for shadow admin paths
pub fn check_dangerous_acl_permissions(domain_dn: &str) -> Result<Vec<ComplianceViolation>, String> {
    let mut violations = Vec::new();

    // =========================================================================
    // CHECK 1: Accounts with DCSync rights
    // DS-Replication-Get-Changes and DS-Replication-Get-Changes-All
    // These are typically granted on the domain head
    // =========================================================================

    // Find accounts with adminCount=1 that are NOT in expected Tier 0 groups
    // These could be shadow admins with delegated permissions
    let admin_count_objects = find_admin_count_objects(domain_dn)?;

    for obj in &admin_count_objects {
        let name = obj.get("name").cloned().unwrap_or_default();
        let sam = obj.get("samaccountname").cloned().unwrap_or_default();
        let dn = obj.get("distinguishedname").cloned().unwrap_or_default();
        let object_class = obj.get("objectclass").cloned().unwrap_or_default();

        // Skip built-in accounts that should have adminCount
        if sam.to_lowercase() == "administrator" ||
           sam.to_lowercase() == "krbtgt" ||
           object_class.to_lowercase().contains("computer") {
            continue;
        }

        // Check if this account is in standard Tier 0 admin groups
        let builtin_memberships = get_builtin_group_memberships(&dn, domain_dn)
            .unwrap_or_default();

        // Check custom tier group memberships
        let tier0_admin_tiers = get_member_admin_tiers(&dn, domain_dn)
            .unwrap_or_default();

        // If account has adminCount=1 but is NOT in any known admin group,
        // it likely has delegated permissions (shadow admin)
        if builtin_memberships.is_empty() && !tier0_admin_tiers.contains(&Tier::Tier0) {
            violations.push(ComplianceViolation {
                violation_type: ViolationType::DangerousAclPermission,
                severity: ViolationSeverity::Critical,
                object_name: name,
                object_dn: dn,
                sam_account_name: sam,
                description: "Account has adminCount=1 but is not a member of any known admin group. \
                             Likely has delegated permissions (Shadow Admin) via direct ACL grants.".to_string(),
                tiers_involved: vec![Tier::Tier0],
                remediation: "Audit ACL permissions on this account. Check for WriteDacl, WriteOwner, \
                             GenericAll rights on Tier 0 objects. Remove delegated permissions or \
                             add to appropriate Tier 0 admin group.".to_string(),
            });
        }
    }

    // =========================================================================
    // CHECK 2: Accounts that can write to AdminSDHolder
    // Anyone who can write to AdminSDHolder effectively controls all protected accounts
    // =========================================================================
    // Note: This requires reading the ACL of AdminSDHolder which needs special handling
    // For now, we flag any non-standard accounts with adminCount=1 as potential risks

    // =========================================================================
    // CHECK 3: Accounts with msDS-AllowedToActOnBehalfOfOtherIdentity on DCs
    // This is a DCSync-equivalent attack path via RBCD
    // Already handled in check_delegation_violations() for RBCD detection
    // =========================================================================

    // =========================================================================
    // CHECK 4: Group Policy Creator Owners membership audit
    // Members can create GPOs and potentially link them to impact Tier 0
    // =========================================================================
    let gpo_creators_filter = "(&(objectClass=group)(sAMAccountName=Group Policy Creator Owners))";

    let gpo_group_results = ldap_search(
        domain_dn,
        gpo_creators_filter,
        &["distinguishedName"],
        SearchScope::Subtree,
    ).unwrap_or_default();

    if let Some(gpo_group) = gpo_group_results.first() {
        if let Some(gpo_group_dn) = gpo_group.get("distinguishedname") {
            // Find members of Group Policy Creator Owners
            let member_filter = format!(
                "(&(objectCategory=person)(objectClass=user)(memberOf:{}:={}))",
                LDAP_MATCHING_RULE_IN_CHAIN,
                escape_ldap_filter(gpo_group_dn)
            );

            let members = ldap_search(
                domain_dn,
                &member_filter,
                &["name", "sAMAccountName", "distinguishedName"],
                SearchScope::Subtree,
            ).unwrap_or_default();

            for member in members {
                let name = member.get("name").cloned().unwrap_or_default();
                let sam = member.get("samaccountname").cloned().unwrap_or_default();
                let member_dn = member.get("distinguishedname").cloned().unwrap_or_default();

                // Skip if member is in Tier 0
                let member_tier = Tier::from_dn(&member_dn);
                if member_tier != Some(Tier::Tier0) {
                    violations.push(ComplianceViolation {
                        violation_type: ViolationType::DangerousAclPermission,
                        severity: ViolationSeverity::High,
                        object_name: name,
                        object_dn: member_dn,
                        sam_account_name: sam,
                        description: "Non-Tier0 account is member of Group Policy Creator Owners. \
                                     Can create GPOs that may impact Tier 0 if linked inappropriately.".to_string(),
                        tiers_involved: vec![member_tier.unwrap_or(Tier::Tier2), Tier::Tier0],
                        remediation: "Remove from Group Policy Creator Owners or move account to Tier 0. \
                                     GPO creation should be restricted to Tier 0 administrators.".to_string(),
                    });
                }
            }
        }
    }

    // =========================================================================
    // CHECK 5: DnsAdmins group membership
    // DnsAdmins can load arbitrary DLLs on DNS servers (typically DCs)
    // MITRE ATT&CK: T1574.002
    // =========================================================================
    let dnsadmins_filter = "(&(objectClass=group)(sAMAccountName=DnsAdmins))";

    let dns_group_results = ldap_search(
        domain_dn,
        dnsadmins_filter,
        &["distinguishedName"],
        SearchScope::Subtree,
    ).unwrap_or_default();

    if let Some(dns_group) = dns_group_results.first() {
        if let Some(dns_group_dn) = dns_group.get("distinguishedname") {
            // Find members of DnsAdmins
            let member_filter = format!(
                "(&(objectCategory=person)(objectClass=user)(memberOf:{}:={}))",
                LDAP_MATCHING_RULE_IN_CHAIN,
                escape_ldap_filter(dns_group_dn)
            );

            let members = ldap_search(
                domain_dn,
                &member_filter,
                &["name", "sAMAccountName", "distinguishedName"],
                SearchScope::Subtree,
            ).unwrap_or_default();

            for member in members {
                let name = member.get("name").cloned().unwrap_or_default();
                let sam = member.get("samaccountname").cloned().unwrap_or_default();
                let member_dn = member.get("distinguishedname").cloned().unwrap_or_default();

                // Flag if member is not in Tier 0
                let member_tier = Tier::from_dn(&member_dn);
                if member_tier != Some(Tier::Tier0) {
                    // Also check if they're in a built-in admin group
                    let builtin_memberships = get_builtin_group_memberships(&member_dn, domain_dn)
                        .unwrap_or_default();

                    if builtin_memberships.is_empty() {
                        violations.push(ComplianceViolation {
                            violation_type: ViolationType::DangerousAclPermission,
                            severity: ViolationSeverity::Critical,
                            object_name: name,
                            object_dn: member_dn,
                            sam_account_name: sam,
                            description: "Non-Tier0 account is member of DnsAdmins. Can load arbitrary DLLs \
                                         on DNS servers (typically Domain Controllers) for code execution.".to_string(),
                            tiers_involved: vec![member_tier.unwrap_or(Tier::Tier2), Tier::Tier0],
                            remediation: "Remove from DnsAdmins or move account to Tier 0. \
                                         DnsAdmins is a Tier 0 equivalent group due to DC code execution.".to_string(),
                        });
                    }
                }
            }
        }
    }

    tracing::info!(
        violations = violations.len(),
        "ACL-based attack path check completed"
    );

    Ok(violations)
}

// ============================================================================
// PAW SECURITY VERIFICATION
// MITRE ATT&CK: T1003.001
// ============================================================================

/// Check PAW (Privileged Access Workstation) security status
///
/// PAWs should have:
/// - Credential Guard enabled (protects LSASS memory)
/// - Secure Boot enabled
/// - TPM present
///
/// Note: Full verification requires WMI queries to the actual machines.
/// This function flags PAWs that cannot be verified as potentially insecure.
///
/// # Arguments
/// * `domain_dn` - Domain distinguished name
///
/// # Returns
/// * Vector of compliance violations for unverified PAWs
pub fn check_paw_security(domain_dn: &str) -> Result<Vec<ComplianceViolation>, String> {
    use crate::infrastructure::ad_search::discover_tier0_infrastructure;

    let mut violations = Vec::new();

    // Get Tier 0 infrastructure to find PAWs
    let tier0_components = discover_tier0_infrastructure(domain_dn)
        .map_err(|e| format!("Failed to discover Tier 0 infrastructure: {:?}", e))?;

    for component in tier0_components {
        // Check if this is a PAW
        if matches!(component.role_type, crate::domain::Tier0RoleType::PAW) {
            // Since we can't query Credential Guard status via LDAP alone,
            // flag all PAWs as requiring verification
            violations.push(ComplianceViolation {
                violation_type: ViolationType::UnverifiedPawSecurity,
                severity: ViolationSeverity::High,
                object_name: component.name.clone(),
                object_dn: component.distinguished_name.clone(),
                sam_account_name: component.name.clone(),
                description: format!(
                    "PAW '{}' security features not verified. Credential Guard status unknown. \
                     OS: {}",
                    component.name,
                    component.operating_system.as_deref().unwrap_or("Unknown")
                ),
                tiers_involved: vec![Tier::Tier0],
                remediation: "Verify Credential Guard is enabled on this PAW:\n\
                             1. Run 'msinfo32' and check 'Credential Guard, Hypervisor enforced'\n\
                             2. Or run: Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard\n\
                             3. Ensure RequiredSecurityProperties includes Credential Guard".to_string(),
            });
        }
    }

    tracing::info!(
        paw_count = violations.len(),
        "PAW security verification check completed"
    );

    Ok(violations)
}

// ============================================================================
// PROTECTED USERS GROUP COMPLIANCE
// MITRE ATT&CK: T1558.003
// ============================================================================

/// Check if Tier 0 administrators are members of the Protected Users group.
///
/// Protected Users group provides:
/// - No NTLM authentication
/// - No DES or RC4 Kerberos encryption
/// - No credential delegation
/// - No credential caching
/// - 4-hour TGT lifetime
///
/// # Arguments
/// * `domain_dn` - Domain distinguished name
///
/// # Returns
/// * Vector of compliance violations for Tier 0 admins not in Protected Users
pub fn check_protected_users_compliance(domain_dn: &str) -> Result<Vec<ComplianceViolation>, String> {
    let mut violations = Vec::new();

    // Find the Protected Users group DN
    let protected_users_filter = "(&(objectClass=group)(sAMAccountName=Protected Users))";

    let group_results = ldap_search(
        domain_dn,
        protected_users_filter,
        &["distinguishedName"],
        SearchScope::Subtree,
    ).map_err(|e| format!("Failed to find Protected Users group: {:?}", e))?;

    let protected_users_dn = match group_results.first() {
        Some(result) => result.get("distinguishedname").cloned().unwrap_or_default(),
        None => {
            tracing::warn!("Protected Users group not found in domain");
            return Ok(violations);
        }
    };

    // Get all Tier 0 admin group members
    let tier0_groups_ou = format!("OU=Groups,OU=Tier0,{}", domain_dn);

    // Find Tier0-Admins and Tier0-Operators groups
    for group_suffix in &["Admins", "Operators"] {
        let group_name = format!("Tier0-{}", group_suffix);
        let group_filter = format!(
            "(&(objectClass=group)(sAMAccountName={}))",
            escape_ldap_filter(&group_name)
        );

        let tier0_group_results = ldap_search(
            &tier0_groups_ou,
            &group_filter,
            &["distinguishedName"],
            SearchScope::OneLevel,
        ).unwrap_or_default();

        if let Some(tier0_group) = tier0_group_results.first() {
            if let Some(tier0_group_dn) = tier0_group.get("distinguishedname") {
                // Find all members of this Tier 0 group
                let member_filter = format!(
                    "(&(objectCategory=person)(objectClass=user)(memberOf:{}:={}))",
                    LDAP_MATCHING_RULE_IN_CHAIN,
                    escape_ldap_filter(tier0_group_dn)
                );

                let members = ldap_search(
                    domain_dn,
                    &member_filter,
                    &["name", "sAMAccountName", "distinguishedName"],
                    SearchScope::Subtree,
                ).unwrap_or_default();

                // Check each member for Protected Users membership
                for member in members {
                    let name = member.get("name").cloned().unwrap_or_default();
                    let sam = member.get("samaccountname").cloned().unwrap_or_default();
                    let member_dn = member.get("distinguishedname").cloned().unwrap_or_default();

                    // Check if member is in Protected Users
                    let in_protected_filter = format!(
                        "(&(distinguishedName={})(memberOf:{}:={}))",
                        escape_ldap_filter(&member_dn),
                        LDAP_MATCHING_RULE_IN_CHAIN,
                        escape_ldap_filter(&protected_users_dn)
                    );

                    let in_protected = ldap_search(
                        domain_dn,
                        &in_protected_filter,
                        &["distinguishedName"],
                        SearchScope::Subtree,
                    ).map(|r| !r.is_empty()).unwrap_or(false);

                    if !in_protected {
                        violations.push(ComplianceViolation {
                            violation_type: ViolationType::MissingProtectedUsers,
                            severity: ViolationSeverity::Critical,
                            object_name: name,
                            object_dn: member_dn,
                            sam_account_name: sam,
                            description: format!(
                                "Tier 0 administrator ({}) not in Protected Users group. \
                                 Credentials vulnerable to NTLM relay, credential caching, and delegation attacks.",
                                group_name
                            ),
                            tiers_involved: vec![Tier::Tier0],
                            remediation: "Add account to Protected Users group. Verify application compatibility first - \
                                         Protected Users cannot use NTLM, DES, or credential delegation.".to_string(),
                        });
                    }
                }
            }
        }
    }

    tracing::info!(
        violations = violations.len(),
        "Protected Users compliance check completed"
    );

    Ok(violations)
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
///
/// Also checks for built-in privileged group memberships (Domain Admins,
/// Enterprise Admins, etc.) which implicitly grant Tier 0 access.

pub fn check_cross_tier_access(domain_dn: &str) -> Result<Vec<CrossTierAccess>, String> {
    use std::collections::{HashMap, HashSet};
    use crate::infrastructure::ad_search::LDAP_MATCHING_RULE_IN_CHAIN;

    let mut violations = Vec::new();

    // Map to track which users are in which tier groups
    let mut user_tier_map: HashMap<String, HashSet<Tier>> = HashMap::new();
    let mut user_groups_map: HashMap<String, Vec<String>> = HashMap::new();
    let mut user_dn_map: HashMap<String, String> = HashMap::new();

    // Check each tier's custom groups
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

    // ============================================================================
    // CHECK BUILT-IN PRIVILEGED GROUPS
    // Members of Domain Admins, Enterprise Admins, etc. are implicitly Tier 0
    // principals. If they also have access to Tier 1 or Tier 2 groups, that's
    // a cross-tier violation.
    // ============================================================================
    for builtin_group in BUILTIN_PRIVILEGED_GROUPS {
        // Find the built-in group DN
        let group_filter = format!(
            "(&(objectClass=group)(sAMAccountName={}))",
            escape_ldap_filter(builtin_group)
        );

        let group_results = ldap_search(
            domain_dn,
            &group_filter,
            &["distinguishedName"],
            SearchScope::Subtree,
        ).unwrap_or_default();

        if let Some(group_result) = group_results.first() {
            if let Some(group_dn) = group_result.get("distinguishedname") {
                // Find all members of this built-in group (transitively)
                let member_filter = format!(
                    "(&(objectCategory=person)(objectClass=user)(memberOf:{}:={}))",
                    LDAP_MATCHING_RULE_IN_CHAIN,
                    escape_ldap_filter(group_dn)
                );

                if let Ok(member_results) = ldap_search(
                    domain_dn,
                    &member_filter,
                    &["sAMAccountName", "distinguishedName"],
                    SearchScope::Subtree,
                ) {
                    for user in member_results {
                        let sam = user.get("samaccountname").cloned().unwrap_or_default();
                        let dn = user.get("distinguishedname").cloned().unwrap_or_default();

                        if !sam.is_empty() {
                            // Built-in privileged group = implicit Tier 0 access
                            user_tier_map
                                .entry(sam.clone())
                                .or_default()
                                .insert(Tier::Tier0);
                            user_groups_map
                                .entry(sam.clone())
                                .or_default()
                                .push(format!("{} (built-in)", builtin_group));
                            user_dn_map
                                .entry(sam)
                                .or_insert(dn);
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
        "Cross-tier access check completed (including built-in groups)"
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

    // Check AdminSDHolder violations (protected accounts in wrong tiers)
    let adminsdholder_violations = check_admin_sdholder_violations(domain_dn)?;
    for violation in adminsdholder_violations {
        status.add_violation(violation);
    }

    // Check Kerberos delegation vulnerabilities (CRITICAL - can bypass tier model)
    let delegation_violations = check_delegation_violations(domain_dn)?;
    for violation in delegation_violations {
        status.add_violation(violation);
    }

    // Check Protected Users group compliance for Tier 0 admins
    let protected_users_violations = check_protected_users_compliance(domain_dn)?;
    for violation in protected_users_violations {
        status.add_violation(violation);
    }

    // Check ACL-based attack paths (Shadow Admins, dangerous group memberships)
    let acl_violations = check_dangerous_acl_permissions(domain_dn)?;
    for violation in acl_violations {
        status.add_violation(violation);
    }

    // Check PAW security (Credential Guard verification)
    let paw_violations = check_paw_security(domain_dn)?;
    for violation in paw_violations {
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
