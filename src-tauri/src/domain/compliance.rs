//! Compliance types and definitions for AD Tier Model
//!
//! Defines structures for tracking tier model compliance and violations.

use serde::{Deserialize, Serialize};
use super::tier::Tier;

/// Type of compliance violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ViolationType {
    /// User has access to multiple tiers
    CrossTierAccess,
    /// Tier 0 infrastructure not in correct OU
    MisplacedTier0Infrastructure,
    /// Account in wrong tier OU
    WrongTierPlacement,
    /// Missing required group membership
    MissingGroupMembership,
    /// Stale/inactive account
    StaleAccount,
    /// Service account with interactive logon
    ServiceAccountInteractiveLogon,
    /// Object not assigned to any tier
    UnassignedObject,
    // ============================================================================
    // KERBEROS DELEGATION ATTACK PATHS
    // ============================================================================
    /// Computer/user with unconstrained delegation (TRUSTED_FOR_DELEGATION)
    /// MITRE ATT&CK: T1558.001, T1558.004
    UnconstrainedDelegation,
    /// Computer/user with constrained delegation (msDS-AllowedToDelegateTo)
    /// MITRE ATT&CK: T1558.003
    ConstrainedDelegation,
    /// Computer with Resource-Based Constrained Delegation configured
    /// MITRE ATT&CK: T1134.002
    ResourceBasedConstrainedDelegation,
    // ============================================================================
    // CREDENTIAL PROTECTION
    // ============================================================================
    /// Tier 0 admin not in Protected Users group
    /// MITRE ATT&CK: T1558.003
    MissingProtectedUsers,
    /// PAW without verified Credential Guard
    /// MITRE ATT&CK: T1003.001
    UnverifiedPawSecurity,
    // ============================================================================
    // ACL-BASED ATTACK PATHS (SHADOW ADMINS)
    // ============================================================================
    /// Non-Tier0 principal with dangerous ACL permissions on Tier 0 objects
    /// Includes: GenericAll, WriteDacl, WriteOwner, ForceChangePassword
    /// MITRE ATT&CK: T1222.001, T1078.002
    DangerousAclPermission,
}

impl ViolationType {
    pub fn severity(&self) -> ViolationSeverity {
        match self {
            ViolationType::CrossTierAccess => ViolationSeverity::Critical,
            ViolationType::MisplacedTier0Infrastructure => ViolationSeverity::High,
            ViolationType::WrongTierPlacement => ViolationSeverity::Medium,
            ViolationType::MissingGroupMembership => ViolationSeverity::Low,
            ViolationType::StaleAccount => ViolationSeverity::Medium,
            ViolationType::ServiceAccountInteractiveLogon => ViolationSeverity::High,
            ViolationType::UnassignedObject => ViolationSeverity::High,
            // Kerberos delegation - all critical as they bypass tier model
            ViolationType::UnconstrainedDelegation => ViolationSeverity::Critical,
            ViolationType::ConstrainedDelegation => ViolationSeverity::High,
            ViolationType::ResourceBasedConstrainedDelegation => ViolationSeverity::Critical,
            // Credential protection
            ViolationType::MissingProtectedUsers => ViolationSeverity::Critical,
            ViolationType::UnverifiedPawSecurity => ViolationSeverity::High,
            // ACL-based attacks (shadow admins)
            ViolationType::DangerousAclPermission => ViolationSeverity::Critical,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ViolationType::CrossTierAccess => "Account has access to multiple tiers, violating tier separation",
            ViolationType::MisplacedTier0Infrastructure => "Critical infrastructure not protected in Tier 0 OU",
            ViolationType::WrongTierPlacement => "Object is in wrong tier OU based on its role",
            ViolationType::MissingGroupMembership => "Object missing required tier group membership",
            ViolationType::StaleAccount => "Account has not logged in for extended period",
            ViolationType::ServiceAccountInteractiveLogon => "Service account capable of interactive logon",
            ViolationType::UnassignedObject => "Object not assigned to any tier in the AD tiering model",
            // Kerberos delegation
            ViolationType::UnconstrainedDelegation => "Unconstrained delegation allows TGT capture from any authenticating user - complete tier bypass",
            ViolationType::ConstrainedDelegation => "Constrained delegation can be abused for S4U2Self/S4U2Proxy privilege escalation",
            ViolationType::ResourceBasedConstrainedDelegation => "RBCD allows privilege escalation from any principal with write access",
            // Credential protection
            ViolationType::MissingProtectedUsers => "Tier 0 admin not in Protected Users group - vulnerable to credential theft",
            ViolationType::UnverifiedPawSecurity => "PAW without verified Credential Guard - Tier 0 credentials exposed to memory scraping",
            // ACL-based attacks
            ViolationType::DangerousAclPermission => "Non-Tier0 principal with dangerous permissions (GenericAll/WriteDacl/WriteOwner) on Tier 0 objects",
        }
    }
}

/// Severity of a violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViolationSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// A compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceViolation {
    /// Type of violation
    pub violation_type: ViolationType,
    /// Severity level
    pub severity: ViolationSeverity,
    /// Object that has the violation
    pub object_name: String,
    /// Distinguished name of the object
    pub object_dn: String,
    /// SAM account name
    pub sam_account_name: String,
    /// Detailed description of the violation
    pub description: String,
    /// Tiers involved (for cross-tier violations)
    pub tiers_involved: Vec<Tier>,
    /// Recommended remediation action
    pub remediation: String,
}

/// Cross-tier access details
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossTierAccess {
    /// User or account with cross-tier access
    pub account_name: String,
    /// Distinguished name
    pub account_dn: String,
    /// Tiers the account has access to
    pub tiers: Vec<Tier>,
    /// Groups providing the access
    pub groups: Vec<String>,
}

/// Overall compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceStatus {
    /// Overall compliance score (0-100)
    pub score: u8,
    /// Total number of violations
    pub total_violations: usize,
    /// Critical violations count
    pub critical_count: usize,
    /// High severity violations count
    pub high_count: usize,
    /// Medium severity violations count
    pub medium_count: usize,
    /// Low severity violations count
    pub low_count: usize,
    /// List of violations
    pub violations: Vec<ComplianceViolation>,
    /// Cross-tier access instances
    pub cross_tier_access: Vec<CrossTierAccess>,
    /// Last check timestamp
    pub last_checked: String,
}

impl ComplianceStatus {
    pub fn new() -> Self {
        Self {
            score: 100,
            total_violations: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            violations: Vec::new(),
            cross_tier_access: Vec::new(),
            last_checked: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn add_violation(&mut self, violation: ComplianceViolation) {
        match violation.severity {
            ViolationSeverity::Critical => self.critical_count += 1,
            ViolationSeverity::High => self.high_count += 1,
            ViolationSeverity::Medium => self.medium_count += 1,
            ViolationSeverity::Low => self.low_count += 1,
        }
        self.total_violations += 1;
        self.violations.push(violation);
        self.calculate_score();
    }

    pub fn add_cross_tier_access(&mut self, access: CrossTierAccess) {
        self.cross_tier_access.push(access);
    }

    fn calculate_score(&mut self) {
        // Score calculation: start at 100, deduct points for violations
        // Critical: -10, High: -5, Medium: -2, Low: -1
        let deductions = self.critical_count * 10
            + self.high_count * 5
            + self.medium_count * 2
            + self.low_count;

        self.score = 100u8.saturating_sub(deductions.min(100) as u8);
    }
}

impl Default for ComplianceStatus {
    fn default() -> Self {
        Self::new()
    }
}
