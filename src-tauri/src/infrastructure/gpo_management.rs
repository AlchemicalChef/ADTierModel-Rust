//! GPO Management for AD Tier Model
//!
//! This module provides functions to create and configure Group Policy Objects
//! for enforcing tier isolation through logon restrictions.

use crate::domain::Tier;
use crate::error::AppResult;
#[cfg(windows)]
use crate::error::AppError;
use serde::{Deserialize, Serialize};

/// Status of a GPO
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GpoStatus {
    pub name: String,
    pub exists: bool,
    pub linked: bool,
    pub link_enabled: bool,
    pub target_ou: String,
    pub created: Option<String>,
    pub modified: Option<String>,
}

/// Status of tier logon restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TierGpoStatus {
    pub tier: String,
    pub base_policy: GpoStatus,
    pub logon_restrictions: GpoStatus,
    pub restrictions_configured: bool,
    pub deny_local_logon: Vec<String>,
    pub deny_rdp_logon: Vec<String>,
    pub deny_network_logon: Vec<String>,
}

/// Result from GPO configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GpoConfigResult {
    pub success: bool,
    pub gpos_created: Vec<String>,
    pub gpos_configured: Vec<String>,
    pub gpos_linked: Vec<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl GpoConfigResult {
    pub fn new() -> Self {
        Self {
            success: true,
            gpos_created: Vec::new(),
            gpos_configured: Vec::new(),
            gpos_linked: Vec::new(),
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

/// Get the GPO status for all tiers
#[cfg(windows)]
pub fn get_all_gpo_status(domain_dn: &str) -> AppResult<Vec<TierGpoStatus>> {
    use std::process::Command;

    let mut statuses = Vec::new();

    for tier in Tier::all() {
        let tier_name = tier.to_string();
        let base_name = format!("SEC-{}-BasePolicy", tier_name);
        let logon_name = format!("SEC-{}-LogonRestrictions", tier_name);
        let target_ou = format!("OU={},{}", tier_name, domain_dn);

        // PowerShell script to get GPO status
        let ps_script = format!(
            r#"
            Import-Module GroupPolicy -ErrorAction Stop
            $result = @{{}}

            # Check base policy GPO
            $baseGpo = Get-GPO -Name '{base_name}' -ErrorAction SilentlyContinue
            if ($baseGpo) {{
                $result.baseExists = $true
                $result.baseCreated = $baseGpo.CreationTime.ToString('o')
                $result.baseModified = $baseGpo.ModificationTime.ToString('o')

                # Check if linked
                $links = Get-GPInheritance -Target '{target_ou}' -ErrorAction SilentlyContinue
                $baseLink = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{base_name}' }}
                $result.baseLinked = $null -ne $baseLink
                $result.baseLinkEnabled = if ($baseLink) {{ $baseLink.Enabled }} else {{ $false }}
            }} else {{
                $result.baseExists = $false
                $result.baseLinked = $false
                $result.baseLinkEnabled = $false
            }}

            # Check logon restrictions GPO
            $logonGpo = Get-GPO -Name '{logon_name}' -ErrorAction SilentlyContinue
            if ($logonGpo) {{
                $result.logonExists = $true
                $result.logonCreated = $logonGpo.CreationTime.ToString('o')
                $result.logonModified = $logonGpo.ModificationTime.ToString('o')

                # Check if linked
                $logonLink = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{logon_name}' }}
                $result.logonLinked = $null -ne $logonLink
                $result.logonLinkEnabled = if ($logonLink) {{ $logonLink.Enabled }} else {{ $false }}

                # Check configured restrictions using GPO report
                $report = Get-GPOReport -Name '{logon_name}' -ReportType Xml -ErrorAction SilentlyContinue
                if ($report) {{
                    $result.restrictionsConfigured = $report -match 'SeDenyInteractiveLogonRight|SeDenyRemoteInteractiveLogonRight|SeDenyNetworkLogonRight'
                }} else {{
                    $result.restrictionsConfigured = $false
                }}
            }} else {{
                $result.logonExists = $false
                $result.logonLinked = $false
                $result.logonLinkEnabled = $false
                $result.restrictionsConfigured = $false
            }}

            $result | ConvertTo-Json -Compress
            "#,
            base_name = base_name,
            logon_name = logon_name,
            target_ou = target_ou,
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
            .output()
            .map_err(|e| AppError::LdapError(format!("Failed to execute PowerShell: {}", e)))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Parse JSON result
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                statuses.push(TierGpoStatus {
                    tier: tier_name.clone(),
                    base_policy: GpoStatus {
                        name: base_name,
                        exists: json["baseExists"].as_bool().unwrap_or(false),
                        linked: json["baseLinked"].as_bool().unwrap_or(false),
                        link_enabled: json["baseLinkEnabled"].as_bool().unwrap_or(false),
                        target_ou: target_ou.clone(),
                        created: json["baseCreated"].as_str().map(|s| s.to_string()),
                        modified: json["baseModified"].as_str().map(|s| s.to_string()),
                    },
                    logon_restrictions: GpoStatus {
                        name: logon_name,
                        exists: json["logonExists"].as_bool().unwrap_or(false),
                        linked: json["logonLinked"].as_bool().unwrap_or(false),
                        link_enabled: json["logonLinkEnabled"].as_bool().unwrap_or(false),
                        target_ou: target_ou.clone(),
                        created: json["logonCreated"].as_str().map(|s| s.to_string()),
                        modified: json["logonModified"].as_str().map(|s| s.to_string()),
                    },
                    restrictions_configured: json["restrictionsConfigured"].as_bool().unwrap_or(false),
                    deny_local_logon: get_deny_groups_for_tier(*tier, "local"),
                    deny_rdp_logon: get_deny_groups_for_tier(*tier, "rdp"),
                    deny_network_logon: get_deny_groups_for_tier(*tier, "network"),
                });
            }
        } else {
            // GPO module not available or error - return unconfigured status
            statuses.push(TierGpoStatus {
                tier: tier_name.clone(),
                base_policy: GpoStatus {
                    name: base_name,
                    exists: false,
                    linked: false,
                    link_enabled: false,
                    target_ou: target_ou.clone(),
                    created: None,
                    modified: None,
                },
                logon_restrictions: GpoStatus {
                    name: logon_name,
                    exists: false,
                    linked: false,
                    link_enabled: false,
                    target_ou: target_ou.clone(),
                    created: None,
                    modified: None,
                },
                restrictions_configured: false,
                deny_local_logon: get_deny_groups_for_tier(*tier, "local"),
                deny_rdp_logon: get_deny_groups_for_tier(*tier, "rdp"),
                deny_network_logon: get_deny_groups_for_tier(*tier, "network"),
            });
        }
    }

    Ok(statuses)
}

#[cfg(not(windows))]
pub fn get_all_gpo_status(domain_dn: &str) -> AppResult<Vec<TierGpoStatus>> {
    // Mock data for non-Windows development
    let mut statuses = Vec::new();

    for tier in Tier::all() {
        let tier_name = tier.to_string();
        let base_name = format!("SEC-{}-BasePolicy", tier_name);
        let logon_name = format!("SEC-{}-LogonRestrictions", tier_name);
        let target_ou = format!("OU={},{}", tier_name, domain_dn);

        // Simulate Tier0 as configured, others as not
        let is_configured = *tier == Tier::Tier0;

        statuses.push(TierGpoStatus {
            tier: tier_name.clone(),
            base_policy: GpoStatus {
                name: base_name,
                exists: is_configured,
                linked: is_configured,
                link_enabled: is_configured,
                target_ou: target_ou.clone(),
                created: if is_configured { Some("2024-11-01T10:00:00Z".to_string()) } else { None },
                modified: if is_configured { Some("2024-11-15T14:30:00Z".to_string()) } else { None },
            },
            logon_restrictions: GpoStatus {
                name: logon_name,
                exists: is_configured,
                linked: is_configured,
                link_enabled: is_configured,
                target_ou: target_ou.clone(),
                created: if is_configured { Some("2024-11-01T10:05:00Z".to_string()) } else { None },
                modified: if is_configured { Some("2024-11-15T14:35:00Z".to_string()) } else { None },
            },
            restrictions_configured: is_configured,
            deny_local_logon: get_deny_groups_for_tier(*tier, "local"),
            deny_rdp_logon: get_deny_groups_for_tier(*tier, "rdp"),
            deny_network_logon: get_deny_groups_for_tier(*tier, "network"),
        });
    }

    Ok(statuses)
}

/// Get the groups that should be denied for a tier
fn get_deny_groups_for_tier(tier: Tier, logon_type: &str) -> Vec<String> {
    match tier {
        Tier::Tier0 => {
            // Tier 0: Deny Tier1 and Tier2 admins
            vec![
                "Tier1-Admins".to_string(),
                "Tier1-Operators".to_string(),
                "Tier2-Admins".to_string(),
                "Tier2-Operators".to_string(),
            ]
        }
        Tier::Tier1 => {
            // Tier 1: Deny Tier0 and Tier2 admins
            // (Tier0 shouldn't log into Tier1, Tier2 definitely shouldn't)
            match logon_type {
                "local" | "rdp" => vec![
                    "Tier0-Admins".to_string(),
                    "Tier2-Admins".to_string(),
                    "Tier2-Operators".to_string(),
                ],
                _ => vec![
                    "Tier2-Admins".to_string(),
                    "Tier2-Operators".to_string(),
                ],
            }
        }
        Tier::Tier2 => {
            // Tier 2: Deny Tier0 and Tier1 admins interactive logon
            match logon_type {
                "local" | "rdp" => vec![
                    "Tier0-Admins".to_string(),
                    "Tier1-Admins".to_string(),
                    "Tier1-Operators".to_string(),
                ],
                _ => vec![],
            }
        }
    }
}

/// Create and configure GPOs for a specific tier
#[cfg(windows)]
pub fn configure_tier_gpos(tier: Tier, domain_dn: &str) -> AppResult<GpoConfigResult> {
    use std::process::Command;

    let mut result = GpoConfigResult::new();
    let tier_name = tier.to_string();
    let base_name = format!("SEC-{}-BasePolicy", tier_name);
    let logon_name = format!("SEC-{}-LogonRestrictions", tier_name);
    let target_ou = format!("OU={},{}", tier_name, domain_dn);

    // Get the groups to deny
    let deny_local = get_deny_groups_for_tier(tier, "local");
    let deny_rdp = get_deny_groups_for_tier(tier, "rdp");
    let deny_network = get_deny_groups_for_tier(tier, "network");

    // Build the deny lists for the INF file
    let deny_local_str = deny_local.join(",");
    let deny_rdp_str = deny_rdp.join(",");
    let deny_network_str = deny_network.join(",");

    // PowerShell script to create GPOs and configure restrictions
    let ps_script = format!(
        r#"
        $ErrorActionPreference = 'Stop'
        Import-Module GroupPolicy

        $results = @{{
            created = @()
            configured = @()
            linked = @()
            errors = @()
            warnings = @()
        }}

        try {{
            # Create base policy GPO if needed
            $baseGpo = Get-GPO -Name '{base_name}' -ErrorAction SilentlyContinue
            if (-not $baseGpo) {{
                $baseGpo = New-GPO -Name '{base_name}' -Comment 'Base security policy for {tier}'
                $results.created += '{base_name}'
            }}

            # Create logon restrictions GPO if needed
            $logonGpo = Get-GPO -Name '{logon_name}' -ErrorAction SilentlyContinue
            if (-not $logonGpo) {{
                $logonGpo = New-GPO -Name '{logon_name}' -Comment 'Logon restrictions for {tier} - Enforces tier isolation'
                $results.created += '{logon_name}'
            }}

            # Link GPOs to target OU
            $links = Get-GPInheritance -Target '{target_ou}' -ErrorAction SilentlyContinue

            if (-not ($links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{base_name}' }})) {{
                New-GPLink -Name '{base_name}' -Target '{target_ou}' -LinkEnabled Yes -ErrorAction SilentlyContinue
                $results.linked += '{base_name}'
            }}

            if (-not ($links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{logon_name}' }})) {{
                New-GPLink -Name '{logon_name}' -Target '{target_ou}' -LinkEnabled Yes -Order 1 -ErrorAction SilentlyContinue
                $results.linked += '{logon_name}'
            }}

            # Configure logon restrictions using security template
            # Create a temporary INF file with the security settings
            $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
"@

            # Add deny rights if we have groups to deny
            $denyLocal = '{deny_local}'
            $denyRdp = '{deny_rdp}'
            $denyNetwork = '{deny_network}'

            if ($denyLocal) {{
                $infContent += "`nSeDenyInteractiveLogonRight = $denyLocal"
            }}
            if ($denyRdp) {{
                $infContent += "`nSeDenyRemoteInteractiveLogonRight = $denyRdp"
            }}
            if ($denyNetwork -and '{tier}' -eq 'Tier0') {{
                # Only apply network deny for Tier0
                $infContent += "`nSeDenyNetworkLogonRight = $denyNetwork"
            }}

            # Create temp file and import
            $tempInf = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.inf'
            $infContent | Out-File -FilePath $tempInf -Encoding Unicode

            # Get GPO path
            $gpoPath = $logonGpo.Path
            $machineFolder = "\\$((Get-ADDomain).PDCEmulator)\SYSVOL\$((Get-ADDomain).DNSRoot)\Policies\{{{0}}}\Machine" -f $logonGpo.Id

            # Create Machine\Microsoft\Windows NT\SecEdit folder if needed
            $secEditPath = Join-Path $machineFolder 'Microsoft\Windows NT\SecEdit'
            if (-not (Test-Path $secEditPath)) {{
                New-Item -Path $secEditPath -ItemType Directory -Force | Out-Null
            }}

            # Copy INF to GptTmpl.inf
            $gptTmplPath = Join-Path $secEditPath 'GptTmpl.inf'
            Copy-Item -Path $tempInf -Destination $gptTmplPath -Force

            # Update gpt.ini to increment version
            $gptIniPath = "\\$((Get-ADDomain).PDCEmulator)\SYSVOL\$((Get-ADDomain).DNSRoot)\Policies\{{{0}}}\gpt.ini" -f $logonGpo.Id
            if (Test-Path $gptIniPath) {{
                $gptIni = Get-Content $gptIniPath
                $version = 0
                foreach ($line in $gptIni) {{
                    if ($line -match 'Version=(\d+)') {{
                        $version = [int]$matches[1]
                    }}
                }}
                $newVersion = $version + 1
                $gptIni = $gptIni -replace 'Version=\d+', "Version=$newVersion"

                # Add machine extension GUIDs if not present
                if ($gptIni -notmatch 'gPCMachineExtensionNames') {{
                    $gptIni += "`ngPCMachineExtensionNames=[{{827D319E-6EAC-11D2-A4EA-00C04F79F83A}}{{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}}]"
                }}

                $gptIni | Out-File -FilePath $gptIniPath -Encoding ASCII
            }}

            # Cleanup temp file
            Remove-Item -Path $tempInf -Force -ErrorAction SilentlyContinue

            $results.configured += '{logon_name}'

        }} catch {{
            $results.errors += $_.Exception.Message
        }}

        $results | ConvertTo-Json -Compress
        "#,
        base_name = base_name,
        logon_name = logon_name,
        tier = tier_name,
        target_ou = target_ou,
        deny_local = deny_local_str,
        deny_rdp = deny_rdp_str,
        deny_network = deny_network_str,
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .map_err(|e| AppError::LdapError(format!("Failed to execute PowerShell: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stderr.is_empty() && !output.status.success() {
        result.add_error(format!("PowerShell error: {}", stderr));
    }

    // Parse the JSON result
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(created) = json["created"].as_array() {
            for item in created {
                if let Some(s) = item.as_str() {
                    result.gpos_created.push(s.to_string());
                }
            }
        }
        if let Some(configured) = json["configured"].as_array() {
            for item in configured {
                if let Some(s) = item.as_str() {
                    result.gpos_configured.push(s.to_string());
                }
            }
        }
        if let Some(linked) = json["linked"].as_array() {
            for item in linked {
                if let Some(s) = item.as_str() {
                    result.gpos_linked.push(s.to_string());
                }
            }
        }
        if let Some(errors) = json["errors"].as_array() {
            for item in errors {
                if let Some(s) = item.as_str() {
                    result.add_error(s.to_string());
                }
            }
        }
        if let Some(warnings) = json["warnings"].as_array() {
            for item in warnings {
                if let Some(s) = item.as_str() {
                    result.add_warning(s.to_string());
                }
            }
        }
    }

    Ok(result)
}

#[cfg(not(windows))]
pub fn configure_tier_gpos(tier: Tier, _domain_dn: &str) -> AppResult<GpoConfigResult> {
    // Mock implementation for non-Windows
    let tier_name = tier.to_string();
    let mut result = GpoConfigResult::new();

    result.gpos_created.push(format!("SEC-{}-BasePolicy", tier_name));
    result.gpos_created.push(format!("SEC-{}-LogonRestrictions", tier_name));
    result.gpos_configured.push(format!("SEC-{}-LogonRestrictions", tier_name));
    result.gpos_linked.push(format!("SEC-{}-BasePolicy", tier_name));
    result.gpos_linked.push(format!("SEC-{}-LogonRestrictions", tier_name));

    Ok(result)
}

/// Configure GPOs for all tiers
pub fn configure_all_tier_gpos(domain_dn: &str) -> AppResult<GpoConfigResult> {
    let mut combined_result = GpoConfigResult::new();

    for tier in Tier::all() {
        match configure_tier_gpos(*tier, domain_dn) {
            Ok(result) => {
                combined_result.gpos_created.extend(result.gpos_created);
                combined_result.gpos_configured.extend(result.gpos_configured);
                combined_result.gpos_linked.extend(result.gpos_linked);
                combined_result.warnings.extend(result.warnings);
                if !result.success {
                    combined_result.success = false;
                    combined_result.errors.extend(result.errors);
                }
            }
            Err(e) => {
                combined_result.add_error(format!("Failed to configure {} GPOs: {}", tier, e));
            }
        }
    }

    Ok(combined_result)
}

/// Delete GPOs for a tier (for cleanup/reset)
#[cfg(windows)]
pub fn delete_tier_gpos(tier: Tier, _domain_dn: &str) -> AppResult<Vec<String>> {
    use std::process::Command;

    let tier_name = tier.to_string();
    let base_name = format!("SEC-{}-BasePolicy", tier_name);
    let logon_name = format!("SEC-{}-LogonRestrictions", tier_name);

    let ps_script = format!(
        r#"
        Import-Module GroupPolicy -ErrorAction Stop
        $deleted = @()

        $baseGpo = Get-GPO -Name '{base_name}' -ErrorAction SilentlyContinue
        if ($baseGpo) {{
            Remove-GPO -Name '{base_name}' -Confirm:$false
            $deleted += '{base_name}'
        }}

        $logonGpo = Get-GPO -Name '{logon_name}' -ErrorAction SilentlyContinue
        if ($logonGpo) {{
            Remove-GPO -Name '{logon_name}' -Confirm:$false
            $deleted += '{logon_name}'
        }}

        $deleted | ConvertTo-Json -Compress
        "#,
        base_name = base_name,
        logon_name = logon_name,
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .map_err(|e| AppError::LdapError(format!("Failed to execute PowerShell: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(deleted) = serde_json::from_str::<Vec<String>>(&stdout) {
        Ok(deleted)
    } else {
        Ok(Vec::new())
    }
}

#[cfg(not(windows))]
pub fn delete_tier_gpos(tier: Tier, _domain_dn: &str) -> AppResult<Vec<String>> {
    let tier_name = tier.to_string();
    Ok(vec![
        format!("SEC-{}-BasePolicy", tier_name),
        format!("SEC-{}-LogonRestrictions", tier_name),
    ])
}
