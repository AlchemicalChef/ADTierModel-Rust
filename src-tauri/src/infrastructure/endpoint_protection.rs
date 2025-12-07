//! Endpoint Protection GPO Management
//!
//! This module provides functions to create and configure Group Policy Objects
//! for endpoint protection including audit policies and Defender settings.

use crate::domain::Tier;
use crate::error::AppResult;

use crate::error::AppError;
use serde::{Deserialize, Serialize};

/// Types of endpoint protection GPOs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EndpointGpoType {
    /// Microsoft baseline audit policies (per-tier)
    AuditBaseline,
    /// ACSC/NSA enhanced audit policies with PowerShell logging (per-tier)
    AuditEnhanced,
    /// Essential DC audit policies (DC OU only)
    DcAuditEssential,
    /// Comprehensive DC audit policies (DC OU only)
    DcAuditComprehensive,
    /// Defender antivirus settings (domain-wide)
    DefenderProtection,
}

impl EndpointGpoType {
    /// Get the GPO name for this type
    pub fn gpo_name(&self, tier: Option<Tier>) -> String {
        match self {
            EndpointGpoType::AuditBaseline => {
                if let Some(t) = tier {
                    format!("SEC-{}-Audit-Baseline", t)
                } else {
                    "SEC-Audit-Baseline".to_string()
                }
            }
            EndpointGpoType::AuditEnhanced => {
                if let Some(t) = tier {
                    format!("SEC-{}-Audit-Enhanced", t)
                } else {
                    "SEC-Audit-Enhanced".to_string()
                }
            }
            EndpointGpoType::DcAuditEssential => "SEC-DC-Audit-Essential".to_string(),
            EndpointGpoType::DcAuditComprehensive => "SEC-DC-Audit-Comprehensive".to_string(),
            EndpointGpoType::DefenderProtection => "SEC-Defender-Protection".to_string(),
        }
    }

    /// Get the description for this GPO type
    pub fn description(&self) -> &'static str {
        match self {
            EndpointGpoType::AuditBaseline => "Microsoft recommended baseline audit policies for Windows endpoints",
            EndpointGpoType::AuditEnhanced => "ACSC/NSA hardened audit policies with PowerShell and command line logging",
            EndpointGpoType::DcAuditEssential => "Essential security audit policies for Domain Controllers",
            EndpointGpoType::DcAuditComprehensive => "Comprehensive forensic audit policies for Domain Controllers",
            EndpointGpoType::DefenderProtection => "Microsoft Defender Antivirus balanced protection settings",
        }
    }

    /// Get the link scope for this GPO type
    pub fn link_scope(&self) -> &'static str {
        match self {
            EndpointGpoType::AuditBaseline | EndpointGpoType::AuditEnhanced => "per-tier",
            EndpointGpoType::DcAuditEssential | EndpointGpoType::DcAuditComprehensive => "dc-only",
            EndpointGpoType::DefenderProtection => "domain-wide",
        }
    }

    /// Get all endpoint GPO types
    pub fn all() -> &'static [EndpointGpoType] {
        &[
            EndpointGpoType::AuditBaseline,
            EndpointGpoType::AuditEnhanced,
            EndpointGpoType::DcAuditEssential,
            EndpointGpoType::DcAuditComprehensive,
            EndpointGpoType::DefenderProtection,
        ]
    }
}

/// Status of an endpoint protection GPO
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointGpoStatus {
    pub gpo_type: String,
    pub name: String,
    pub description: String,
    pub exists: bool,
    pub linked: bool,
    pub link_target: String,
    pub link_scope: String,
    pub created: Option<String>,
    pub modified: Option<String>,
    /// For per-tier GPOs, the status of each tier
    pub tier_status: Option<Vec<TierLinkStatus>>,
}

/// Link status for a specific tier
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TierLinkStatus {
    pub tier: String,
    pub linked: bool,
    pub link_enabled: bool,
}

/// Result from endpoint GPO configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointGpoConfigResult {
    pub success: bool,
    pub gpo_type: String,
    pub gpo_name: String,
    pub created: bool,
    pub linked: bool,
    pub configured: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl EndpointGpoConfigResult {
    pub fn new(gpo_type: &str, gpo_name: &str) -> Self {
        Self {
            success: true,
            gpo_type: gpo_type.to_string(),
            gpo_name: gpo_name.to_string(),
            created: false,
            linked: false,
            configured: false,
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

/// Get status of all endpoint protection GPOs

pub fn get_all_endpoint_gpo_status(domain_dn: &str) -> AppResult<Vec<EndpointGpoStatus>> {
    use std::process::Command;

    let mut statuses = Vec::new();

    // Check per-tier audit GPOs
    for gpo_type in &[EndpointGpoType::AuditBaseline, EndpointGpoType::AuditEnhanced] {
        let mut tier_statuses = Vec::new();
        let mut any_exists = false;
        let mut any_linked = false;
        let mut created: Option<String> = None;
        let mut modified: Option<String> = None;

        for tier in Tier::all() {
            let gpo_name = gpo_type.gpo_name(Some(*tier));
            let target_ou = format!("OU={},{}", tier, domain_dn);

            let ps_script = format!(
                r#"
                Import-Module GroupPolicy -ErrorAction Stop
                $result = @{{}}
                $gpo = Get-GPO -Name '{gpo_name}' -ErrorAction SilentlyContinue
                if ($gpo) {{
                    $result.exists = $true
                    $result.created = $gpo.CreationTime.ToString('o')
                    $result.modified = $gpo.ModificationTime.ToString('o')
                    $links = Get-GPInheritance -Target '{target_ou}' -ErrorAction SilentlyContinue
                    $link = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{gpo_name}' }}
                    $result.linked = $null -ne $link
                    $result.linkEnabled = if ($link) {{ $link.Enabled }} else {{ $false }}
                }} else {{
                    $result.exists = $false
                    $result.linked = $false
                    $result.linkEnabled = $false
                }}
                $result | ConvertTo-Json -Compress
                "#,
                gpo_name = gpo_name,
                target_ou = target_ou,
            );

            let output = Command::new("powershell")
                .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
                .output()
                .map_err(|e| AppError::LdapError(format!("Failed to execute PowerShell: {}", e)))?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                    let exists = json["exists"].as_bool().unwrap_or(false);
                    let linked = json["linked"].as_bool().unwrap_or(false);
                    let link_enabled = json["linkEnabled"].as_bool().unwrap_or(false);

                    if exists {
                        any_exists = true;
                        if created.is_none() {
                            created = json["created"].as_str().map(|s| s.to_string());
                            modified = json["modified"].as_str().map(|s| s.to_string());
                        }
                    }
                    if linked {
                        any_linked = true;
                    }

                    tier_statuses.push(TierLinkStatus {
                        tier: tier.to_string(),
                        linked,
                        link_enabled,
                    });
                }
            }
        }

        statuses.push(EndpointGpoStatus {
            gpo_type: format!("{:?}", gpo_type),
            name: gpo_type.gpo_name(None),
            description: gpo_type.description().to_string(),
            exists: any_exists,
            linked: any_linked,
            link_target: "Per-Tier OUs".to_string(),
            link_scope: gpo_type.link_scope().to_string(),
            created,
            modified,
            tier_status: Some(tier_statuses),
        });
    }

    // Check DC audit GPOs
    for gpo_type in &[EndpointGpoType::DcAuditEssential, EndpointGpoType::DcAuditComprehensive] {
        let gpo_name = gpo_type.gpo_name(None);
        let dc_ou = format!("OU=Domain Controllers,{}", domain_dn);

        let ps_script = format!(
            r#"
            Import-Module GroupPolicy -ErrorAction Stop
            $result = @{{}}
            $gpo = Get-GPO -Name '{gpo_name}' -ErrorAction SilentlyContinue
            if ($gpo) {{
                $result.exists = $true
                $result.created = $gpo.CreationTime.ToString('o')
                $result.modified = $gpo.ModificationTime.ToString('o')
                $links = Get-GPInheritance -Target '{dc_ou}' -ErrorAction SilentlyContinue
                $link = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{gpo_name}' }}
                $result.linked = $null -ne $link
                $result.linkEnabled = if ($link) {{ $link.Enabled }} else {{ $false }}
            }} else {{
                $result.exists = $false
                $result.linked = $false
                $result.linkEnabled = $false
            }}
            $result | ConvertTo-Json -Compress
            "#,
            gpo_name = gpo_name,
            dc_ou = dc_ou,
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
            .output()
            .map_err(|e| AppError::LdapError(format!("Failed to execute PowerShell: {}", e)))?;

        let (exists, linked, created, modified) = if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                (
                    json["exists"].as_bool().unwrap_or(false),
                    json["linked"].as_bool().unwrap_or(false),
                    json["created"].as_str().map(|s| s.to_string()),
                    json["modified"].as_str().map(|s| s.to_string()),
                )
            } else {
                (false, false, None, None)
            }
        } else {
            (false, false, None, None)
        };

        statuses.push(EndpointGpoStatus {
            gpo_type: format!("{:?}", gpo_type),
            name: gpo_name,
            description: gpo_type.description().to_string(),
            exists,
            linked,
            link_target: dc_ou,
            link_scope: gpo_type.link_scope().to_string(),
            created,
            modified,
            tier_status: None,
        });
    }

    // Check Defender GPO
    let gpo_type = EndpointGpoType::DefenderProtection;
    let gpo_name = gpo_type.gpo_name(None);

    let ps_script = format!(
        r#"
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop
        $result = @{{}}
        $domain = Get-ADDomain -ErrorAction Stop
        $domainDN = $domain.DistinguishedName
        $gpo = Get-GPO -Name '{gpo_name}' -ErrorAction SilentlyContinue
        if ($gpo) {{
            $result.exists = $true
            $result.created = $gpo.CreationTime.ToString('o')
            $result.modified = $gpo.ModificationTime.ToString('o')
            $links = Get-GPInheritance -Target $domainDN -ErrorAction SilentlyContinue
            $link = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{gpo_name}' }}
            $result.linked = $null -ne $link
            $result.linkEnabled = if ($link) {{ $link.Enabled }} else {{ $false }}
            $result.linkTarget = $domainDN
        }} else {{
            $result.exists = $false
            $result.linked = $false
            $result.linkEnabled = $false
            $result.linkTarget = $domainDN
        }}
        $result | ConvertTo-Json -Compress
        "#,
        gpo_name = gpo_name,
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .map_err(|e| AppError::LdapError(format!("Failed to execute PowerShell: {}", e)))?;

    let (exists, linked, link_target, created, modified) = if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            (
                json["exists"].as_bool().unwrap_or(false),
                json["linked"].as_bool().unwrap_or(false),
                json["linkTarget"].as_str().unwrap_or(domain_dn).to_string(),
                json["created"].as_str().map(|s| s.to_string()),
                json["modified"].as_str().map(|s| s.to_string()),
            )
        } else {
            (false, false, domain_dn.to_string(), None, None)
        }
    } else {
        (false, false, domain_dn.to_string(), None, None)
    };

    statuses.push(EndpointGpoStatus {
        gpo_type: format!("{:?}", gpo_type),
        name: gpo_name,
        description: gpo_type.description().to_string(),
        exists,
        linked,
        link_target,
        link_scope: gpo_type.link_scope().to_string(),
        created,
        modified,
        tier_status: None,
    });

    Ok(statuses)
}

/// Configure the baseline audit policy GPO for a specific tier
pub fn configure_audit_baseline_gpo(tier: Tier, domain_dn: &str) -> AppResult<EndpointGpoConfigResult> {
    use std::process::Command;

    let gpo_type = EndpointGpoType::AuditBaseline;
    let gpo_name = gpo_type.gpo_name(Some(tier));
    let target_ou = format!("OU={},{}", tier, domain_dn);
    let mut result = EndpointGpoConfigResult::new("AuditBaseline", &gpo_name);

    // PowerShell script to create and configure baseline audit GPO
    let ps_script = format!(
        r#"
        $ErrorActionPreference = 'Continue'
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop

        $results = @{{
            created = $false
            linked = $false
            configured = $false
            errors = @()
            warnings = @()
        }}

        try {{
            $domain = Get-ADDomain -ErrorAction Stop

            # Create GPO if needed
            $gpo = Get-GPO -Name '{gpo_name}' -ErrorAction SilentlyContinue
            if (-not $gpo) {{
                $gpo = New-GPO -Name '{gpo_name}' -Comment '{description}'
                $results.created = $true
            }}

            # Link to target OU
            $links = Get-GPInheritance -Target '{target_ou}' -ErrorAction SilentlyContinue
            $existingLink = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{gpo_name}' }}
            if (-not $existingLink) {{
                New-GPLink -Name '{gpo_name}' -Target '{target_ou}' -LinkEnabled Yes -ErrorAction Stop | Out-Null
                $results.linked = $true
            }} else {{
                $results.linked = $true
            }}

            # Configure audit policies via GptTmpl.inf
            $gpoGuid = "{{" + $gpo.Id.ToString().ToUpper() + "}}"
            $sysvolPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
            $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
            $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

            # Create directory if needed
            if (-not (Test-Path $secEditPath)) {{
                New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
            }}

            # Audit policy values:
            # 0 = No auditing, 1 = Success, 2 = Failure, 3 = Success and Failure
            $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 2
AuditPrivilegeUse = 2
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 0
AuditDSAccess = 0
AuditAccountLogon = 3
"@

            $infContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force

            # Update GPT.INI with Security CSE GUID
            $gptIniPath = Join-Path $sysvolPath "GPT.INI"
            $cseGuid = "[{{827D319E-6EAC-11D2-A4EA-00C04F79F83A}}{{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}}]"

            # Get current version
            $adGpo = Get-ADObject -Filter "Name -eq '$gpoGuid'" -SearchBase "CN=Policies,CN=System,$($domain.DistinguishedName)" -Properties versionNumber -ErrorAction SilentlyContinue
            $currentVersion = 0
            if ($adGpo) {{
                $currentVersion = $adGpo.versionNumber
            }}
            $newVersion = $currentVersion + 1

            $gptContent = @"
[General]
Version=$newVersion
gPCMachineExtensionNames=$cseGuid
"@
            $gptContent | Out-File -FilePath $gptIniPath -Encoding ASCII -Force

            # Update AD version
            if ($adGpo) {{
                Set-ADObject -Identity $adGpo -Replace @{{versionNumber = $newVersion}} -ErrorAction SilentlyContinue
            }}

            $results.configured = $true

            # Harden GPO permissions for tier-matched access control
            $tierAdminGroup = '{tier_admin_group}'
            try {{
                $gpoGuid = $gpo.Id

                # Remove CREATOR OWNER permissions
                Set-GPPermission -Guid $gpoGuid -TargetName 'S-1-3-0' -TargetType WellKnownGroup -PermissionLevel None -Replace -ErrorAction SilentlyContinue

                # Grant tier admin group full edit rights
                Set-GPPermission -Guid $gpoGuid -TargetName $tierAdminGroup -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction SilentlyContinue

                # Ensure Authenticated Users can apply
                Set-GPPermission -Guid $gpoGuid -TargetName 'Authenticated Users' -TargetType WellKnownGroup -PermissionLevel GpoApply -ErrorAction SilentlyContinue

                $results.warnings += "Hardened permissions on {gpo_name} for $tierAdminGroup"
            }} catch {{
                $results.warnings += "Could not harden {gpo_name} permissions: $($_.Exception.Message)"
            }}

        }} catch {{
            $results.errors += $_.Exception.Message
        }}

        $results | ConvertTo-Json -Compress
        "#,
        gpo_name = gpo_name,
        target_ou = target_ou,
        description = gpo_type.description(),
        tier_admin_group = format!("{}-Admins", tier),
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .map_err(|e| AppError::GpoError(format!("Failed to execute PowerShell: {}", e)))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            result.created = json["created"].as_bool().unwrap_or(false);
            result.linked = json["linked"].as_bool().unwrap_or(false);
            result.configured = json["configured"].as_bool().unwrap_or(false);
            result.success = result.configured;

            if let Some(errors) = json["errors"].as_array() {
                for err in errors {
                    if let Some(msg) = err.as_str() {
                        result.add_error(msg.to_string());
                    }
                }
            }
            if let Some(warnings) = json["warnings"].as_array() {
                for warn in warnings {
                    if let Some(msg) = warn.as_str() {
                        result.add_warning(msg.to_string());
                    }
                }
            }
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        result.add_error(format!("PowerShell execution failed: {}", stderr));
    }

    Ok(result)
}

/// Configure the enhanced audit policy GPO for a specific tier
pub fn configure_audit_enhanced_gpo(tier: Tier, domain_dn: &str) -> AppResult<EndpointGpoConfigResult> {
    use std::process::Command;

    let gpo_type = EndpointGpoType::AuditEnhanced;
    let gpo_name = gpo_type.gpo_name(Some(tier));
    let target_ou = format!("OU={},{}", tier, domain_dn);
    let mut result = EndpointGpoConfigResult::new("AuditEnhanced", &gpo_name);

    // PowerShell script with enhanced audit settings including PowerShell logging
    let ps_script = format!(
        r#"
        $ErrorActionPreference = 'Continue'
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop

        $results = @{{
            created = $false
            linked = $false
            configured = $false
            errors = @()
            warnings = @()
        }}

        try {{
            $domain = Get-ADDomain -ErrorAction Stop

            # Create GPO if needed
            $gpo = Get-GPO -Name '{gpo_name}' -ErrorAction SilentlyContinue
            if (-not $gpo) {{
                $gpo = New-GPO -Name '{gpo_name}' -Comment '{description}'
                $results.created = $true
            }}

            # Link to target OU
            $links = Get-GPInheritance -Target '{target_ou}' -ErrorAction SilentlyContinue
            $existingLink = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{gpo_name}' }}
            if (-not $existingLink) {{
                New-GPLink -Name '{gpo_name}' -Target '{target_ou}' -LinkEnabled Yes -ErrorAction Stop | Out-Null
                $results.linked = $true
            }} else {{
                $results.linked = $true
            }}

            # Configure audit policies via GptTmpl.inf
            $gpoGuid = "{{" + $gpo.Id.ToString().ToUpper() + "}}"
            $sysvolPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
            $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
            $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

            # Create directory if needed
            if (-not (Test-Path $secEditPath)) {{
                New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
            }}

            # Enhanced audit policy values (more comprehensive)
            $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 1
AuditDSAccess = 3
AuditAccountLogon = 3
[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled=4,1
"@

            $infContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force

            # Configure PowerShell logging via registry.pol
            # Use GPO registry preferences for PowerShell settings
            $registryPath = Join-Path $sysvolPath "Machine\Registry.pol"

            # Set PowerShell logging via Set-GPRegistryValue
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ValueName 'EnableScriptBlockLogging' -Type DWord -Value 1 -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ValueName 'EnableModuleLogging' -Type DWord -Value 1 -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ValueName 'EnableTranscripting' -Type DWord -Value 1 -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ValueName 'EnableInvocationHeader' -Type DWord -Value 1 -ErrorAction SilentlyContinue

            # Update GPT.INI with Security CSE GUID and Registry CSE
            $gptIniPath = Join-Path $sysvolPath "GPT.INI"
            $cseGuids = "[{{827D319E-6EAC-11D2-A4EA-00C04F79F83A}}{{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}}][{{35378EAC-683F-11D2-A89A-00C04FBBCFA2}}{{D02B1F72-3407-48AE-BA88-E8213C6761F1}}]"

            # Get current version
            $adGpo = Get-ADObject -Filter "Name -eq '$gpoGuid'" -SearchBase "CN=Policies,CN=System,$($domain.DistinguishedName)" -Properties versionNumber -ErrorAction SilentlyContinue
            $currentVersion = 0
            if ($adGpo) {{
                $currentVersion = $adGpo.versionNumber
            }}
            $newVersion = $currentVersion + 1

            $gptContent = @"
[General]
Version=$newVersion
gPCMachineExtensionNames=$cseGuids
"@
            $gptContent | Out-File -FilePath $gptIniPath -Encoding ASCII -Force

            # Update AD version
            if ($adGpo) {{
                Set-ADObject -Identity $adGpo -Replace @{{versionNumber = $newVersion}} -ErrorAction SilentlyContinue
            }}

            $results.configured = $true

            # Harden GPO permissions for tier-matched access control
            $tierAdminGroup = '{tier_admin_group}'
            try {{
                $gpoGuidId = $gpo.Id

                # Remove CREATOR OWNER permissions
                Set-GPPermission -Guid $gpoGuidId -TargetName 'S-1-3-0' -TargetType WellKnownGroup -PermissionLevel None -Replace -ErrorAction SilentlyContinue

                # Grant tier admin group full edit rights
                Set-GPPermission -Guid $gpoGuidId -TargetName $tierAdminGroup -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction SilentlyContinue

                # Ensure Authenticated Users can apply
                Set-GPPermission -Guid $gpoGuidId -TargetName 'Authenticated Users' -TargetType WellKnownGroup -PermissionLevel GpoApply -ErrorAction SilentlyContinue

                $results.warnings += "Hardened permissions on {gpo_name} for $tierAdminGroup"
            }} catch {{
                $results.warnings += "Could not harden {gpo_name} permissions: $($_.Exception.Message)"
            }}

        }} catch {{
            $results.errors += $_.Exception.Message
        }}

        $results | ConvertTo-Json -Compress
        "#,
        gpo_name = gpo_name,
        target_ou = target_ou,
        description = gpo_type.description(),
        tier_admin_group = format!("{}-Admins", tier),
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .map_err(|e| AppError::GpoError(format!("Failed to execute PowerShell: {}", e)))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            result.created = json["created"].as_bool().unwrap_or(false);
            result.linked = json["linked"].as_bool().unwrap_or(false);
            result.configured = json["configured"].as_bool().unwrap_or(false);
            result.success = result.configured;

            if let Some(errors) = json["errors"].as_array() {
                for err in errors {
                    if let Some(msg) = err.as_str() {
                        result.add_error(msg.to_string());
                    }
                }
            }
            if let Some(warnings) = json["warnings"].as_array() {
                for warn in warnings {
                    if let Some(msg) = warn.as_str() {
                        result.add_warning(msg.to_string());
                    }
                }
            }
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        result.add_error(format!("PowerShell execution failed: {}", stderr));
    }

    Ok(result)
}

/// Configure the essential DC audit policy GPO
pub fn configure_dc_audit_essential_gpo(domain_dn: &str) -> AppResult<EndpointGpoConfigResult> {
    use std::process::Command;

    let gpo_type = EndpointGpoType::DcAuditEssential;
    let gpo_name = gpo_type.gpo_name(None);
    let dc_ou = format!("OU=Domain Controllers,{}", domain_dn);
    let mut result = EndpointGpoConfigResult::new("DcAuditEssential", &gpo_name);

    let ps_script = format!(
        r#"
        $ErrorActionPreference = 'Continue'
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop

        $results = @{{
            created = $false
            linked = $false
            configured = $false
            errors = @()
            warnings = @()
        }}

        try {{
            $domain = Get-ADDomain -ErrorAction Stop

            # Create GPO if needed
            $gpo = Get-GPO -Name '{gpo_name}' -ErrorAction SilentlyContinue
            if (-not $gpo) {{
                $gpo = New-GPO -Name '{gpo_name}' -Comment '{description}'
                $results.created = $true
            }}

            # Link to Domain Controllers OU
            $links = Get-GPInheritance -Target '{dc_ou}' -ErrorAction SilentlyContinue
            $existingLink = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{gpo_name}' }}
            if (-not $existingLink) {{
                New-GPLink -Name '{gpo_name}' -Target '{dc_ou}' -LinkEnabled Yes -ErrorAction Stop | Out-Null
                $results.linked = $true
            }} else {{
                $results.linked = $true
            }}

            # Configure DC-specific audit policies
            $gpoGuid = "{{" + $gpo.Id.ToString().ToUpper() + "}}"
            $sysvolPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
            $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
            $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

            if (-not (Test-Path $secEditPath)) {{
                New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
            }}

            # Essential DC audit policies
            $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 0
AuditDSAccess = 3
AuditAccountLogon = 3
"@

            $infContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force

            # Update GPT.INI
            $gptIniPath = Join-Path $sysvolPath "GPT.INI"
            $cseGuid = "[{{827D319E-6EAC-11D2-A4EA-00C04F79F83A}}{{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}}]"

            $adGpo = Get-ADObject -Filter "Name -eq '$gpoGuid'" -SearchBase "CN=Policies,CN=System,$($domain.DistinguishedName)" -Properties versionNumber -ErrorAction SilentlyContinue
            $currentVersion = 0
            if ($adGpo) {{
                $currentVersion = $adGpo.versionNumber
            }}
            $newVersion = $currentVersion + 1

            $gptContent = @"
[General]
Version=$newVersion
gPCMachineExtensionNames=$cseGuid
"@
            $gptContent | Out-File -FilePath $gptIniPath -Encoding ASCII -Force

            if ($adGpo) {{
                Set-ADObject -Identity $adGpo -Replace @{{versionNumber = $newVersion}} -ErrorAction SilentlyContinue
            }}

            $results.configured = $true

            # Harden GPO permissions - DC policies are Tier 0 scope
            $tierAdminGroup = 'Tier0-Admins'
            try {{
                $gpoGuidId = $gpo.Id

                # Remove CREATOR OWNER permissions
                Set-GPPermission -Guid $gpoGuidId -TargetName 'S-1-3-0' -TargetType WellKnownGroup -PermissionLevel None -Replace -ErrorAction SilentlyContinue

                # Grant Tier0-Admins full edit rights
                Set-GPPermission -Guid $gpoGuidId -TargetName $tierAdminGroup -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction SilentlyContinue

                # Ensure Authenticated Users can apply
                Set-GPPermission -Guid $gpoGuidId -TargetName 'Authenticated Users' -TargetType WellKnownGroup -PermissionLevel GpoApply -ErrorAction SilentlyContinue

                $results.warnings += "Hardened permissions on {gpo_name} for $tierAdminGroup"
            }} catch {{
                $results.warnings += "Could not harden {gpo_name} permissions: $($_.Exception.Message)"
            }}

        }} catch {{
            $results.errors += $_.Exception.Message
        }}

        $results | ConvertTo-Json -Compress
        "#,
        gpo_name = gpo_name,
        dc_ou = dc_ou,
        description = gpo_type.description(),
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .map_err(|e| AppError::GpoError(format!("Failed to execute PowerShell: {}", e)))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            result.created = json["created"].as_bool().unwrap_or(false);
            result.linked = json["linked"].as_bool().unwrap_or(false);
            result.configured = json["configured"].as_bool().unwrap_or(false);
            result.success = result.configured;

            if let Some(errors) = json["errors"].as_array() {
                for err in errors {
                    if let Some(msg) = err.as_str() {
                        result.add_error(msg.to_string());
                    }
                }
            }
            if let Some(warnings) = json["warnings"].as_array() {
                for warn in warnings {
                    if let Some(msg) = warn.as_str() {
                        result.add_warning(msg.to_string());
                    }
                }
            }
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        result.add_error(format!("PowerShell execution failed: {}", stderr));
    }

    Ok(result)
}

/// Configure the comprehensive DC audit policy GPO
pub fn configure_dc_audit_comprehensive_gpo(domain_dn: &str) -> AppResult<EndpointGpoConfigResult> {
    use std::process::Command;

    let gpo_type = EndpointGpoType::DcAuditComprehensive;
    let gpo_name = gpo_type.gpo_name(None);
    let dc_ou = format!("OU=Domain Controllers,{}", domain_dn);
    let mut result = EndpointGpoConfigResult::new("DcAuditComprehensive", &gpo_name);

    let ps_script = format!(
        r#"
        $ErrorActionPreference = 'Continue'
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop

        $results = @{{
            created = $false
            linked = $false
            configured = $false
            errors = @()
            warnings = @()
        }}

        try {{
            $domain = Get-ADDomain -ErrorAction Stop

            # Create GPO if needed
            $gpo = Get-GPO -Name '{gpo_name}' -ErrorAction SilentlyContinue
            if (-not $gpo) {{
                $gpo = New-GPO -Name '{gpo_name}' -Comment '{description}'
                $results.created = $true
            }}

            # Link to Domain Controllers OU
            $links = Get-GPInheritance -Target '{dc_ou}' -ErrorAction SilentlyContinue
            $existingLink = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{gpo_name}' }}
            if (-not $existingLink) {{
                New-GPLink -Name '{gpo_name}' -Target '{dc_ou}' -LinkEnabled Yes -ErrorAction Stop | Out-Null
                $results.linked = $true
            }} else {{
                $results.linked = $true
            }}

            # Configure comprehensive DC audit policies
            $gpoGuid = "{{" + $gpo.Id.ToString().ToUpper() + "}}"
            $sysvolPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
            $secEditPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit"
            $gptTmplPath = Join-Path $secEditPath "GptTmpl.inf"

            if (-not (Test-Path $secEditPath)) {{
                New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
            }}

            # Comprehensive DC audit policies (all events)
            $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Event Audit]
AuditSystemEvents = 3
AuditLogonEvents = 3
AuditObjectAccess = 3
AuditPrivilegeUse = 3
AuditPolicyChange = 3
AuditAccountManage = 3
AuditProcessTracking = 3
AuditDSAccess = 3
AuditAccountLogon = 3
[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled=4,1
"@

            $infContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force

            # Enable additional DC-specific logging via registry
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ValueName '15 Field Engineering' -Type DWord -Value 5 -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ValueName '16 LDAP Interface Events' -Type DWord -Value 2 -ErrorAction SilentlyContinue

            # Update GPT.INI with both Security and Registry CSE
            $gptIniPath = Join-Path $sysvolPath "GPT.INI"
            $cseGuids = "[{{827D319E-6EAC-11D2-A4EA-00C04F79F83A}}{{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}}][{{35378EAC-683F-11D2-A89A-00C04FBBCFA2}}{{D02B1F72-3407-48AE-BA88-E8213C6761F1}}]"

            $adGpo = Get-ADObject -Filter "Name -eq '$gpoGuid'" -SearchBase "CN=Policies,CN=System,$($domain.DistinguishedName)" -Properties versionNumber -ErrorAction SilentlyContinue
            $currentVersion = 0
            if ($adGpo) {{
                $currentVersion = $adGpo.versionNumber
            }}
            $newVersion = $currentVersion + 1

            $gptContent = @"
[General]
Version=$newVersion
gPCMachineExtensionNames=$cseGuids
"@
            $gptContent | Out-File -FilePath $gptIniPath -Encoding ASCII -Force

            if ($adGpo) {{
                Set-ADObject -Identity $adGpo -Replace @{{versionNumber = $newVersion}} -ErrorAction SilentlyContinue
            }}

            $results.configured = $true

            # Harden GPO permissions - DC policies are Tier 0 scope
            $tierAdminGroup = 'Tier0-Admins'
            try {{
                $gpoGuidId = $gpo.Id

                # Remove CREATOR OWNER permissions
                Set-GPPermission -Guid $gpoGuidId -TargetName 'S-1-3-0' -TargetType WellKnownGroup -PermissionLevel None -Replace -ErrorAction SilentlyContinue

                # Grant Tier0-Admins full edit rights
                Set-GPPermission -Guid $gpoGuidId -TargetName $tierAdminGroup -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction SilentlyContinue

                # Ensure Authenticated Users can apply
                Set-GPPermission -Guid $gpoGuidId -TargetName 'Authenticated Users' -TargetType WellKnownGroup -PermissionLevel GpoApply -ErrorAction SilentlyContinue

                $results.warnings += "Hardened permissions on {gpo_name} for $tierAdminGroup"
            }} catch {{
                $results.warnings += "Could not harden {gpo_name} permissions: $($_.Exception.Message)"
            }}

        }} catch {{
            $results.errors += $_.Exception.Message
        }}

        $results | ConvertTo-Json -Compress
        "#,
        gpo_name = gpo_name,
        dc_ou = dc_ou,
        description = gpo_type.description(),
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .map_err(|e| AppError::GpoError(format!("Failed to execute PowerShell: {}", e)))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            result.created = json["created"].as_bool().unwrap_or(false);
            result.linked = json["linked"].as_bool().unwrap_or(false);
            result.configured = json["configured"].as_bool().unwrap_or(false);
            result.success = result.configured;

            if let Some(errors) = json["errors"].as_array() {
                for err in errors {
                    if let Some(msg) = err.as_str() {
                        result.add_error(msg.to_string());
                    }
                }
            }
            if let Some(warnings) = json["warnings"].as_array() {
                for warn in warnings {
                    if let Some(msg) = warn.as_str() {
                        result.add_warning(msg.to_string());
                    }
                }
            }
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        result.add_error(format!("PowerShell execution failed: {}", stderr));
    }

    Ok(result)
}

/// Configure the Defender protection GPO (domain-wide)
pub fn configure_defender_gpo(domain_dn: &str) -> AppResult<EndpointGpoConfigResult> {
    use std::process::Command;

    let gpo_type = EndpointGpoType::DefenderProtection;
    let gpo_name = gpo_type.gpo_name(None);
    let mut result = EndpointGpoConfigResult::new("DefenderProtection", &gpo_name);

    let ps_script = format!(
        r#"
        $ErrorActionPreference = 'Continue'
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop

        $results = @{{
            created = $false
            linked = $false
            configured = $false
            errors = @()
            warnings = @()
        }}

        try {{
            $domain = Get-ADDomain -ErrorAction Stop
            $domainDN = $domain.DistinguishedName

            # Create GPO if needed
            $gpo = Get-GPO -Name '{gpo_name}' -ErrorAction SilentlyContinue
            if (-not $gpo) {{
                $gpo = New-GPO -Name '{gpo_name}' -Comment '{description}'
                $results.created = $true
            }}

            # Link to domain root
            $links = Get-GPInheritance -Target $domainDN -ErrorAction SilentlyContinue
            $existingLink = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{gpo_name}' }}
            if (-not $existingLink) {{
                New-GPLink -Name '{gpo_name}' -Target $domainDN -LinkEnabled Yes -ErrorAction Stop | Out-Null
                $results.linked = $true
            }} else {{
                $results.linked = $true
            }}

            # Configure Defender settings via registry policies
            # Real-time Protection
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableRealtimeMonitoring' -Type DWord -Value 0 -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableBehaviorMonitoring' -Type DWord -Value 0 -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableOnAccessProtection' -Type DWord -Value 0 -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -ValueName 'DisableScanOnRealtimeEnable' -Type DWord -Value 0 -ErrorAction SilentlyContinue

            # Cloud Protection (MAPS)
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -ValueName 'SpynetReporting' -Type DWord -Value 2 -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -ValueName 'SubmitSamplesConsent' -Type DWord -Value 1 -ErrorAction SilentlyContinue

            # PUA Protection
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'PUAProtection' -Type DWord -Value 1 -ErrorAction SilentlyContinue

            # Scan settings
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -ValueName 'DisableEmailScanning' -Type DWord -Value 0 -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -ValueName 'DisableRemovableDriveScanning' -Type DWord -Value 0 -ErrorAction SilentlyContinue
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -ValueName 'DisableArchiveScanning' -Type DWord -Value 0 -ErrorAction SilentlyContinue

            # Ensure Defender is not disabled
            Set-GPRegistryValue -Name '{gpo_name}' -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -ValueName 'DisableAntiSpyware' -Type DWord -Value 0 -ErrorAction SilentlyContinue

            # Update GPT.INI with Registry CSE
            $gpoGuid = "{{" + $gpo.Id.ToString().ToUpper() + "}}"
            $sysvolPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
            $gptIniPath = Join-Path $sysvolPath "GPT.INI"
            $cseGuids = "[{{35378EAC-683F-11D2-A89A-00C04FBBCFA2}}{{D02B1F72-3407-48AE-BA88-E8213C6761F1}}]"

            $adGpo = Get-ADObject -Filter "Name -eq '$gpoGuid'" -SearchBase "CN=Policies,CN=System,$($domain.DistinguishedName)" -Properties versionNumber -ErrorAction SilentlyContinue
            $currentVersion = 0
            if ($adGpo) {{
                $currentVersion = $adGpo.versionNumber
            }}
            $newVersion = $currentVersion + 1

            $gptContent = @"
[General]
Version=$newVersion
gPCMachineExtensionNames=$cseGuids
"@
            $gptContent | Out-File -FilePath $gptIniPath -Encoding ASCII -Force

            if ($adGpo) {{
                Set-ADObject -Identity $adGpo -Replace @{{versionNumber = $newVersion}} -ErrorAction SilentlyContinue
            }}

            $results.configured = $true

            # Harden GPO permissions - Domain-wide security GPO uses Tier 0 scope
            $tierAdminGroup = 'Tier0-Admins'
            try {{
                $gpoGuidId = $gpo.Id

                # Remove CREATOR OWNER permissions
                Set-GPPermission -Guid $gpoGuidId -TargetName 'S-1-3-0' -TargetType WellKnownGroup -PermissionLevel None -Replace -ErrorAction SilentlyContinue

                # Grant Tier0-Admins full edit rights
                Set-GPPermission -Guid $gpoGuidId -TargetName $tierAdminGroup -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction SilentlyContinue

                # Ensure Authenticated Users can apply
                Set-GPPermission -Guid $gpoGuidId -TargetName 'Authenticated Users' -TargetType WellKnownGroup -PermissionLevel GpoApply -ErrorAction SilentlyContinue

                $results.warnings += "Hardened permissions on {gpo_name} for $tierAdminGroup"
            }} catch {{
                $results.warnings += "Could not harden {gpo_name} permissions: $($_.Exception.Message)"
            }}

        }} catch {{
            $results.errors += $_.Exception.Message
        }}

        $results | ConvertTo-Json -Compress
        "#,
        gpo_name = gpo_name,
        description = gpo_type.description(),
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .map_err(|e| AppError::GpoError(format!("Failed to execute PowerShell: {}", e)))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            result.created = json["created"].as_bool().unwrap_or(false);
            result.linked = json["linked"].as_bool().unwrap_or(false);
            result.configured = json["configured"].as_bool().unwrap_or(false);
            result.success = result.configured;

            if let Some(errors) = json["errors"].as_array() {
                for err in errors {
                    if let Some(msg) = err.as_str() {
                        result.add_error(msg.to_string());
                    }
                }
            }
            if let Some(warnings) = json["warnings"].as_array() {
                for warn in warnings {
                    if let Some(msg) = warn.as_str() {
                        result.add_warning(msg.to_string());
                    }
                }
            }
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        result.add_error(format!("PowerShell execution failed: {}", stderr));
    }

    Ok(result)
}

/// Delete an endpoint protection GPO
pub fn delete_endpoint_gpo(gpo_type: EndpointGpoType, tier: Option<Tier>) -> AppResult<()> {
    use std::process::Command;

    let gpo_name = gpo_type.gpo_name(tier);

    let ps_script = format!(
        r#"
        Import-Module GroupPolicy -ErrorAction Stop
        $gpo = Get-GPO -Name '{gpo_name}' -ErrorAction SilentlyContinue
        if ($gpo) {{
            Remove-GPO -Name '{gpo_name}' -ErrorAction Stop
            @{{ success = $true }} | ConvertTo-Json -Compress
        }} else {{
            @{{ success = $true; message = 'GPO does not exist' }} | ConvertTo-Json -Compress
        }}
        "#,
        gpo_name = gpo_name,
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .map_err(|e| AppError::GpoError(format!("Failed to execute PowerShell: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::GpoError(format!("Failed to delete GPO: {}", stderr)));
    }

    Ok(())
}
