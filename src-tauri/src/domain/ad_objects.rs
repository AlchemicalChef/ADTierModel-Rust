use serde::{Deserialize, Serialize};
use super::tier::Tier;

/// Types of AD objects
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectType {
    User,
    Computer,
    AdminWorkstation,
    Group,
    ServiceAccount,
}

impl ObjectType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "user" => Some(ObjectType::User),
            "computer" => Some(ObjectType::Computer),
            "adminworkstation" => Some(ObjectType::AdminWorkstation),
            "group" => Some(ObjectType::Group),
            "serviceaccount" => Some(ObjectType::ServiceAccount),
            _ => None,
        }
    }
}

/// Tier 0 infrastructure role types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier0RoleType {
    DomainController,
    ADFS,
    EntraConnect,
    CertificateAuthority,
    PAW,
    // FSMO Role Holders
    SchemaMaster,
    DomainNamingMaster,
    RIDMaster,
    PDCEmulator,
    InfrastructureMaster,
    // Additional Tier 0 Infrastructure (MITRE ATT&CK: T1072, T1068)
    /// SCCM/MECM Site Server - has code execution on all managed systems
    SCCM,
    /// Exchange Server - Exchange Trusted Subsystem has WriteDacl on domain
    Exchange,
}

impl Tier0RoleType {
    pub fn display_name(&self) -> &'static str {
        match self {
            Tier0RoleType::DomainController => "Domain Controller",
            Tier0RoleType::ADFS => "AD FS",
            Tier0RoleType::EntraConnect => "Entra Connect",
            Tier0RoleType::CertificateAuthority => "Certificate Authority",
            Tier0RoleType::PAW => "Privileged Access Workstation",
            Tier0RoleType::SchemaMaster => "Schema Master",
            Tier0RoleType::DomainNamingMaster => "Domain Naming Master",
            Tier0RoleType::RIDMaster => "RID Master",
            Tier0RoleType::PDCEmulator => "PDC Emulator",
            Tier0RoleType::InfrastructureMaster => "Infrastructure Master",
            Tier0RoleType::SCCM => "SCCM/MECM Site Server",
            Tier0RoleType::Exchange => "Exchange Server",
        }
    }

    pub fn is_fsmo_role(&self) -> bool {
        matches!(
            self,
            Tier0RoleType::SchemaMaster
                | Tier0RoleType::DomainNamingMaster
                | Tier0RoleType::RIDMaster
                | Tier0RoleType::PDCEmulator
                | Tier0RoleType::InfrastructureMaster
        )
    }

    /// Check if this role type has direct code execution capability on managed systems
    pub fn has_code_execution_capability(&self) -> bool {
        matches!(
            self,
            Tier0RoleType::SCCM | Tier0RoleType::Exchange
        )
    }
}

/// A member of a tier (user, computer, group, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TierMember {
    pub name: String,
    pub sam_account_name: String,
    pub object_type: ObjectType,
    pub tier: Option<Tier>,
    pub enabled: bool,
    pub last_logon: Option<String>,
    pub distinguished_name: String,
    pub description: Option<String>,
    // Computer-specific
    pub operating_system: Option<String>,
    // Tier 0 specific
    pub role_type: Option<Tier0RoleType>,
    // Group-specific
    pub member_count: Option<usize>,
}

impl TierMember {
    /// Create a new TierMember with required fields
    pub fn new(
        name: String,
        sam_account_name: String,
        object_type: ObjectType,
        distinguished_name: String,
    ) -> Self {
        Self {
            name,
            sam_account_name,
            object_type,
            tier: None,
            enabled: true,
            last_logon: None,
            distinguished_name,
            description: None,
            operating_system: None,
            role_type: None,
            member_count: None,
        }
    }
}

/// Domain information from AD connection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainInfo {
    pub domain_dn: String,
    pub dns_root: String,
    pub netbios_name: String,
    pub connected: bool,
}

/// Tier 0 infrastructure component
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tier0Component {
    pub name: String,
    pub role_type: Tier0RoleType,
    pub operating_system: Option<String>,
    pub last_logon: Option<String>,
    pub current_ou: String,
    pub is_in_tier0: bool,
    pub distinguished_name: String,
    pub description: Option<String>,
}
