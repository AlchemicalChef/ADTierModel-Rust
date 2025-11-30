use serde::{Deserialize, Serialize};
use std::fmt;

/// Tier levels in the AD security model
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Tier {
    Tier0,
    Tier1,
    Tier2,
}

impl Tier {
    /// Parse tier from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tier0" | "tier 0" | "t0" => Some(Tier::Tier0),
            "tier1" | "tier 1" | "t1" => Some(Tier::Tier1),
            "tier2" | "tier 2" | "t2" => Some(Tier::Tier2),
            _ => None,
        }
    }

    /// Get the OU relative path for this tier
    pub fn ou_path(&self) -> &'static str {
        match self {
            Tier::Tier0 => "OU=Tier0",
            Tier::Tier1 => "OU=Tier1",
            Tier::Tier2 => "OU=Tier2",
        }
    }

    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Tier::Tier0 => "Tier 0 - Infrastructure",
            Tier::Tier1 => "Tier 1 - Servers",
            Tier::Tier2 => "Tier 2 - Workstations",
        }
    }

    /// Get risk level
    pub fn risk_level(&self) -> RiskLevel {
        match self {
            Tier::Tier0 => RiskLevel::Critical,
            Tier::Tier1 => RiskLevel::High,
            Tier::Tier2 => RiskLevel::Medium,
        }
    }

    /// Get all tiers
    pub fn all() -> &'static [Tier] {
        &[Tier::Tier0, Tier::Tier1, Tier::Tier2]
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tier::Tier0 => write!(f, "Tier0"),
            Tier::Tier1 => write!(f, "Tier1"),
            Tier::Tier2 => write!(f, "Tier2"),
        }
    }
}

/// Risk levels for compliance scoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Critical => write!(f, "Critical"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::Low => write!(f, "Low"),
        }
    }
}

/// Tier configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierConfiguration {
    pub name: String,
    pub description: String,
    pub ou_path: String,
    pub color: String,
    pub risk_level: RiskLevel,
}

impl TierConfiguration {
    pub fn for_tier(tier: Tier, domain_dn: &str) -> Self {
        match tier {
            Tier::Tier0 => TierConfiguration {
                name: "Tier0".to_string(),
                description: "Infrastructure tier - Domain Controllers, ADFS, Entra Connect, CAs, PAWs".to_string(),
                ou_path: format!("OU=Tier0,{}", domain_dn),
                color: "#dc2626".to_string(),
                risk_level: RiskLevel::Critical,
            },
            Tier::Tier1 => TierConfiguration {
                name: "Tier1".to_string(),
                description: "Server tier - Application servers, database servers, file servers".to_string(),
                ou_path: format!("OU=Tier1,{}", domain_dn),
                color: "#ca8a04".to_string(),
                risk_level: RiskLevel::High,
            },
            Tier::Tier2 => TierConfiguration {
                name: "Tier2".to_string(),
                description: "Workstation tier - User workstations and endpoints".to_string(),
                ou_path: format!("OU=Tier2,{}", domain_dn),
                color: "#16a34a".to_string(),
                risk_level: RiskLevel::Medium,
            },
        }
    }
}

/// Tier counts for display
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TierCounts {
    #[serde(rename = "Tier0")]
    pub tier0: usize,
    #[serde(rename = "Tier1")]
    pub tier1: usize,
    #[serde(rename = "Tier2")]
    pub tier2: usize,
    #[serde(rename = "Unassigned")]
    pub unassigned: usize,
}
