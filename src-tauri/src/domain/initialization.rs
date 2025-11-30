//! Initialization types for AD Tier Model setup
//!
//! Types for tracking the initialization process of creating OUs, groups, and permissions.

use serde::{Deserialize, Serialize};
use super::tier::Tier;

/// Group suffixes for tier security groups
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupSuffix {
    Admins,
    Operators,
    Readers,
    ServiceAccounts,
    JumpServers,
}

impl GroupSuffix {
    /// Get all group suffixes
    pub fn all() -> &'static [GroupSuffix] {
        &[
            GroupSuffix::Admins,
            GroupSuffix::Operators,
            GroupSuffix::Readers,
            GroupSuffix::ServiceAccounts,
            GroupSuffix::JumpServers,
        ]
    }

    /// Get the suffix string
    pub fn as_str(&self) -> &'static str {
        match self {
            GroupSuffix::Admins => "Admins",
            GroupSuffix::Operators => "Operators",
            GroupSuffix::Readers => "Readers",
            GroupSuffix::ServiceAccounts => "ServiceAccounts",
            GroupSuffix::JumpServers => "JumpServers",
        }
    }

    /// Get description for the group
    pub fn description(&self) -> &'static str {
        match self {
            GroupSuffix::Admins => "Full administrative access",
            GroupSuffix::Operators => "Operational access for day-to-day tasks",
            GroupSuffix::Readers => "Read-only access",
            GroupSuffix::ServiceAccounts => "Service account access",
            GroupSuffix::JumpServers => "Jump server access",
        }
    }
}

/// Sub-OU types within each tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubOU {
    Computers,
    Users,
    Groups,
    ServiceAccounts,
    AdminWorkstations,
}

impl SubOU {
    /// Get all sub-OUs
    pub fn all() -> &'static [SubOU] {
        &[
            SubOU::Computers,
            SubOU::Users,
            SubOU::Groups,
            SubOU::ServiceAccounts,
            SubOU::AdminWorkstations,
        ]
    }

    /// Get the OU name
    pub fn as_str(&self) -> &'static str {
        match self {
            SubOU::Computers => "Computers",
            SubOU::Users => "Users",
            SubOU::Groups => "Groups",
            SubOU::ServiceAccounts => "ServiceAccounts",
            SubOU::AdminWorkstations => "AdminWorkstations",
        }
    }

    /// Get description for the OU
    pub fn description(&self, tier: Tier) -> String {
        match self {
            SubOU::Computers => format!("{} computer accounts", tier),
            SubOU::Users => format!("{} user accounts", tier),
            SubOU::Groups => format!("{} security groups", tier),
            SubOU::ServiceAccounts => format!("{} service accounts", tier),
            SubOU::AdminWorkstations => format!("{} administrative workstations", tier),
        }
    }
}

/// Options for initializing the AD Tier Model
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializationOptions {
    /// Create the OU structure
    pub create_ou_structure: bool,
    /// Create tier security groups
    pub create_groups: bool,
    /// Set permissions on OUs (requires elevated privileges)
    pub set_permissions: bool,
    /// Create GPOs for logon restrictions
    pub create_gpos: bool,
    /// Force re-creation even if objects exist
    pub force: bool,
}

impl Default for InitializationOptions {
    fn default() -> Self {
        Self {
            create_ou_structure: true,
            create_groups: true,
            set_permissions: false, // Requires elevated privileges
            create_gpos: false,     // Complex operation, disabled by default
            force: false,
        }
    }
}

/// Status of a single initialization step
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitStepStatus {
    pub name: String,
    pub status: StepStatus,
    pub message: Option<String>,
}

/// Status enum for initialization steps
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepStatus {
    Pending,
    InProgress,
    Completed,
    Skipped,
    Failed,
}

/// Progress of the initialization process
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializationProgress {
    pub current_step: usize,
    pub total_steps: usize,
    pub current_operation: String,
    pub steps: Vec<InitStepStatus>,
}

impl InitializationProgress {
    pub fn new(total_steps: usize) -> Self {
        Self {
            current_step: 0,
            total_steps,
            current_operation: "Starting initialization...".to_string(),
            steps: Vec::new(),
        }
    }

    pub fn add_step(&mut self, name: &str, status: StepStatus, message: Option<String>) {
        self.steps.push(InitStepStatus {
            name: name.to_string(),
            status,
            message,
        });
    }

    pub fn percentage(&self) -> f32 {
        if self.total_steps == 0 {
            return 100.0;
        }
        (self.current_step as f32 / self.total_steps as f32) * 100.0
    }
}

/// Results from the initialization process
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializationResult {
    pub success: bool,
    pub ous_created: Vec<String>,
    pub groups_created: Vec<String>,
    pub permissions_set: Vec<String>,
    pub gpos_created: Vec<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl InitializationResult {
    pub fn new() -> Self {
        Self {
            success: true,
            ous_created: Vec::new(),
            groups_created: Vec::new(),
            permissions_set: Vec::new(),
            gpos_created: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn add_error(&mut self, error: String) {
        self.success = false;
        self.errors.push(error);
    }

    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }
}

impl Default for InitializationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Check result for verifying if tier model is already initialized
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializationStatus {
    pub is_initialized: bool,
    pub tier0_ou_exists: bool,
    pub tier1_ou_exists: bool,
    pub tier2_ou_exists: bool,
    pub groups_exist: bool,
    pub missing_components: Vec<String>,
}

impl InitializationStatus {
    pub fn not_initialized() -> Self {
        Self {
            is_initialized: false,
            tier0_ou_exists: false,
            tier1_ou_exists: false,
            tier2_ou_exists: false,
            groups_exist: false,
            missing_components: Vec::new(),
        }
    }
}

/// Generate group name from tier and suffix
pub fn tier_group_name(tier: Tier, suffix: GroupSuffix) -> String {
    format!("{}-{}", tier, suffix.as_str())
}

/// Generate full group DN
pub fn tier_group_dn(tier: Tier, suffix: GroupSuffix, domain_dn: &str) -> String {
    format!(
        "CN={},OU=Groups,{},{}",
        tier_group_name(tier, suffix),
        tier.ou_path(),
        domain_dn
    )
}

/// Generate OU DN for a tier
pub fn tier_ou_dn(tier: Tier, domain_dn: &str) -> String {
    format!("{},{}", tier.ou_path(), domain_dn)
}

/// Generate sub-OU DN
pub fn sub_ou_dn(tier: Tier, sub_ou: SubOU, domain_dn: &str) -> String {
    format!("OU={},{},{}", sub_ou.as_str(), tier.ou_path(), domain_dn)
}
