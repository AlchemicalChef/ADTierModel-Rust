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

                # Check configured restrictions by directly reading GptTmpl.inf from SYSVOL
                $result.restrictionsConfigured = $false
                try {{
                    Import-Module ActiveDirectory -ErrorAction Stop
                    $domain = Get-ADDomain -ErrorAction Stop
                    $gpoGuid = "{{"  + $logonGpo.Id.ToString().ToUpper() + "}}"
                    $sysvolPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
                    $gptTmplPath = Join-Path $sysvolPath "Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

                    if (Test-Path $gptTmplPath) {{
                        $content = Get-Content $gptTmplPath -Raw -ErrorAction SilentlyContinue
                        if ($content -match 'SeDenyInteractiveLogonRight|SeDenyRemoteInteractiveLogonRight') {{
                            $result.restrictionsConfigured = $true
                        }}
                    }}
                }} catch {{
                    # Fall back to GPO report method
                    $report = Get-GPOReport -Name '{logon_name}' -ReportType Xml -ErrorAction SilentlyContinue
                    if ($report -and ($report -match 'SeDenyInteractiveLogonRight|SeDenyRemoteInteractiveLogonRight')) {{
                        $result.restrictionsConfigured = $true
                    }}
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

/// Generate PowerShell script to harden GPO permissions for tier-matched access control
/// This removes CREATOR OWNER permissions and grants edit rights to the appropriate tier admin group
pub fn generate_gpo_permission_hardening_script(gpo_name: &str, tier_admin_group: &str) -> String {
    format!(
        r#"
        # Harden GPO permissions for {gpo_name}
        try {{
            $gpo = Get-GPO -Name '{gpo_name}' -ErrorAction Stop
            $gpoGuid = $gpo.Id

            # Remove CREATOR OWNER permissions (S-1-3-0)
            try {{
                Set-GPPermission -Guid $gpoGuid -TargetName 'S-1-3-0' -TargetType WellKnownGroup -PermissionLevel None -Replace -ErrorAction SilentlyContinue
                $results.warnings += "Removed CREATOR OWNER permissions from {gpo_name}"
            }} catch {{
                $results.warnings += "Could not remove CREATOR OWNER from {gpo_name}: $($_.Exception.Message)"
            }}

            # Grant tier admin group full edit rights
            try {{
                Set-GPPermission -Guid $gpoGuid -TargetName '{tier_admin_group}' -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction Stop
                $results.warnings += "Granted {tier_admin_group} edit rights on {gpo_name}"
            }} catch {{
                $results.warnings += "Could not grant {tier_admin_group} permissions on {gpo_name}: $($_.Exception.Message)"
            }}

            # Ensure Authenticated Users can apply the GPO
            try {{
                Set-GPPermission -Guid $gpoGuid -TargetName 'Authenticated Users' -TargetType WellKnownGroup -PermissionLevel GpoApply -ErrorAction SilentlyContinue
            }} catch {{
                $results.warnings += "Could not set Authenticated Users permissions on {gpo_name}: $($_.Exception.Message)"
            }}
        }} catch {{
            $results.warnings += "Could not harden permissions for {gpo_name}: $($_.Exception.Message)"
        }}
        "#,
        gpo_name = gpo_name,
        tier_admin_group = tier_admin_group,
    )
}

/// Get the tier admin group name for a given tier
pub fn get_tier_admin_group(tier: Tier) -> String {
    format!("{}-Admins", tier)
}

/// Get the groups that should be denied for a tier
fn get_deny_groups_for_tier(tier: Tier, logon_type: &str) -> Vec<String> {
    match tier {
        Tier::Tier0 => {
            // Tier 0: Deny Tier1 and Tier2 admins (lower tiers can't access Tier 0)
            vec![
                "Tier1-Admins".to_string(),
                "Tier1-Operators".to_string(),
                "Tier2-Admins".to_string(),
                "Tier2-Operators".to_string(),
            ]
        }
        Tier::Tier1 => {
            // Tier 1: Deny Tier0 (higher tier) and Tier2 (lower tier)
            match logon_type {
                "local" | "rdp" | "network" => vec![
                    "Tier0-Admins".to_string(),
                    "Tier2-Admins".to_string(),
                    "Tier2-Operators".to_string(),
                ],
                _ => vec![],
            }
        }
        Tier::Tier2 => {
            // Tier 2: Deny Tier0 and Tier1 (higher tiers can't access Tier 2)
            match logon_type {
                "local" | "rdp" | "network" => vec![
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

    // Build the deny lists as PowerShell array strings
    let deny_local_ps: Vec<String> = deny_local.iter().map(|g| format!("'{}'", g)).collect();
    let deny_rdp_ps: Vec<String> = deny_rdp.iter().map(|g| format!("'{}'", g)).collect();
    let deny_network_ps: Vec<String> = deny_network.iter().map(|g| format!("'{}'", g)).collect();

    let deny_local_str = deny_local_ps.join(",");
    let deny_rdp_str = deny_rdp_ps.join(",");
    let deny_network_str = deny_network_ps.join(",");

    // Apply network deny for all tiers to enforce tier isolation
    let apply_network_deny = true;

    // PowerShell script to create GPOs and configure restrictions using SecPol approach
    let ps_script = format!(
        r#"
        $ErrorActionPreference = 'Continue'
        Import-Module GroupPolicy -ErrorAction Stop
        Import-Module ActiveDirectory -ErrorAction Stop

        $results = @{{
            created = @()
            configured = @()
            linked = @()
            errors = @()
            warnings = @()
            debug = @()
        }}

        # Function to resolve group name to SID string for INF file
        function Get-GroupSidString {{
            param([string]$GroupName)
            try {{
                $group = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction Stop
                if ($group) {{
                    return "*" + $group.SID.Value
                }}
                return $null
            }} catch {{
                $results.debug += "Failed to resolve group $GroupName : $_"
                return $null
            }}
        }}

        try {{
            $domain = Get-ADDomain -ErrorAction Stop
            $results.debug += "Domain: $($domain.DNSRoot)"

            # Create base policy GPO if needed
            $baseGpo = Get-GPO -Name '{base_name}' -ErrorAction SilentlyContinue
            if (-not $baseGpo) {{
                $baseGpo = New-GPO -Name '{base_name}' -Comment 'Base security policy for {tier}'
                $results.created += '{base_name}'
                $results.debug += "Created GPO: {base_name}"
            }}

            # Create logon restrictions GPO if needed
            $logonGpo = Get-GPO -Name '{logon_name}' -ErrorAction SilentlyContinue
            if (-not $logonGpo) {{
                $logonGpo = New-GPO -Name '{logon_name}' -Comment 'Logon restrictions for {tier} - Enforces tier isolation'
                $results.created += '{logon_name}'
                $results.debug += "Created GPO: {logon_name}"
            }}

            # Link GPOs to target OU
            try {{
                $links = Get-GPInheritance -Target '{target_ou}' -ErrorAction Stop

                $baseLinked = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{base_name}' }}
                if (-not $baseLinked) {{
                    New-GPLink -Name '{base_name}' -Target '{target_ou}' -LinkEnabled Yes -ErrorAction Stop | Out-Null
                    $results.linked += '{base_name}'
                }}

                $logonLinked = $links.GpoLinks | Where-Object {{ $_.DisplayName -eq '{logon_name}' }}
                if (-not $logonLinked) {{
                    New-GPLink -Name '{logon_name}' -Target '{target_ou}' -LinkEnabled Yes -ErrorAction Stop | Out-Null
                    $results.linked += '{logon_name}'
                }}
            }} catch {{
                $results.warnings += "Could not link GPO to OU: $_. The OU may not exist yet."
            }}

            # Resolve groups to SIDs
            $denyLocalGroups = @({deny_local})
            $denyRdpGroups = @({deny_rdp})
            $denyNetworkGroups = @({deny_network})

            $results.warnings += "Looking for local deny groups: $($denyLocalGroups -join ', ')"

            $denyLocalSids = @()
            foreach ($grp in $denyLocalGroups) {{
                $sid = Get-GroupSidString -GroupName $grp
                if ($sid) {{
                    $denyLocalSids += $sid
                    $results.warnings += "Resolved $grp to $sid"
                }} else {{
                    $results.warnings += "Group NOT FOUND: $grp - Please ensure this group exists"
                }}
            }}

            $denyRdpSids = @()
            foreach ($grp in $denyRdpGroups) {{
                $sid = Get-GroupSidString -GroupName $grp
                if ($sid) {{
                    $denyRdpSids += $sid
                }}
            }}

            $denyNetworkSids = @()
            foreach ($grp in $denyNetworkGroups) {{
                $sid = Get-GroupSidString -GroupName $grp
                if ($sid) {{ $denyNetworkSids += $sid }}
            }}

            $results.warnings += "Resolved $($denyLocalSids.Count) local deny SIDs, $($denyRdpSids.Count) RDP deny SIDs"

            if ($denyLocalSids.Count -eq 0 -and $denyRdpSids.Count -eq 0) {{
                $results.errors += "No tier groups found. Please initialize the tier structure first to create the security groups (Tier0-Admins, Tier1-Admins, etc.)"
                $results | ConvertTo-Json -Depth 3 -Compress
                return
            }}

            # Build the GptTmpl.inf content - proper security template format
            $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
"@
            if ($denyLocalSids.Count -gt 0) {{
                # Deny log on locally
                $infContent += "`r`nSeDenyInteractiveLogonRight = $($denyLocalSids -join ',')"
                $results.warnings += "SeDenyInteractiveLogonRight = $($denyLocalSids -join ',')"

                # Deny log on as a batch job
                $infContent += "`r`nSeDenyBatchLogonRight = $($denyLocalSids -join ',')"
                $results.warnings += "SeDenyBatchLogonRight = $($denyLocalSids -join ',')"

                # Deny log on as a service
                $infContent += "`r`nSeDenyServiceLogonRight = $($denyLocalSids -join ',')"
                $results.warnings += "SeDenyServiceLogonRight = $($denyLocalSids -join ',')"
            }}
            if ($denyRdpSids.Count -gt 0) {{
                # Deny log on through Remote Desktop Services
                $infContent += "`r`nSeDenyRemoteInteractiveLogonRight = $($denyRdpSids -join ',')"
                $results.warnings += "SeDenyRemoteInteractiveLogonRight = $($denyRdpSids -join ',')"
            }}
            if ({apply_network_deny} -and $denyNetworkSids.Count -gt 0) {{
                # Deny access to this computer from the network
                $infContent += "`r`nSeDenyNetworkLogonRight = $($denyNetworkSids -join ',')"
            }}
            $infContent += "`r`n"

            # Get SYSVOL path
            $gpoGuid = "{{"  + $logonGpo.Id.ToString().ToUpper() + "}}"
            $sysvolPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\$gpoGuid"
            $results.debug += "SYSVOL path: $sysvolPath"

            # Create the SecEdit folder structure
            $machineFolder = Join-Path $sysvolPath "Machine"
            $secEditFolder = Join-Path $machineFolder "Microsoft\Windows NT\SecEdit"

            if (-not (Test-Path $secEditFolder)) {{
                New-Item -Path $secEditFolder -ItemType Directory -Force | Out-Null
                $results.debug += "Created SecEdit folder"
            }}

            # Write the GptTmpl.inf file
            $gptTmplPath = Join-Path $secEditFolder "GptTmpl.inf"
            $infContent | Out-File -FilePath $gptTmplPath -Encoding Unicode -Force
            $results.debug += "Wrote GptTmpl.inf to $gptTmplPath"

            # Get current version from AD first
            $adVersion = 0
            $gpoFilter = "displayName -eq '{logon_name}'"
            $gpoDN = Get-ADObject -Filter $gpoFilter -SearchBase "CN=Policies,CN=System,$($domain.DistinguishedName)" -Properties versionNumber -ErrorAction SilentlyContinue
            if ($gpoDN) {{
                $adVersion = [int]$gpoDN.versionNumber
            }}

            # Update GPT.ini to increment version and add CSE GUIDs
            $gptIniPath = Join-Path $sysvolPath "GPT.INI"

            # CSE GUIDs for Security Settings
            # {{827D319E-6EAC-11D2-A4EA-00C04F79F83A}} = Security CSE
            # {{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}} = Security Editor
            $cseGuids = "[{{827D319E-6EAC-11D2-A4EA-00C04F79F83A}}{{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}}]"

            $gptVersion = 0
            if (Test-Path $gptIniPath) {{
                $gptIni = Get-Content $gptIniPath -Raw
                if ($gptIni -match 'Version=(\d+)') {{
                    $gptVersion = [int]$matches[1]
                }}
            }}

            # Use the higher of AD or GPT.INI version, then increment
            $newVersion = [Math]::Max($adVersion, $gptVersion) + 1
            $results.warnings += "Version: AD=$adVersion, GPT.INI=$gptVersion, New=$newVersion"

            # Write GPT.INI with proper format
            $gptIniContent = @"
[General]
Version=$newVersion
gPCMachineExtensionNames=$cseGuids
"@
            Set-Content -Path $gptIniPath -Value $gptIniContent -Encoding ASCII -Force -NoNewline
            $results.debug += "Updated GPT.INI with version $newVersion"

            # Update the AD object's versionNumber attribute to match
            try {{
                if ($gpoDN) {{
                    Set-ADObject -Identity $gpoDN.DistinguishedName -Replace @{{versionNumber=$newVersion}}
                    $results.warnings += "Updated AD GPO versionNumber to $newVersion"
                }} else {{
                    $results.warnings += "Could not find GPO in AD by displayName"
                }}
            }} catch {{
                $results.warnings += "Could not update AD version: $($_.Exception.Message)"
            }}

            # Verify the file was written correctly
            if (Test-Path $gptTmplPath) {{
                $writtenContent = Get-Content $gptTmplPath -Raw -ErrorAction SilentlyContinue
                if ($writtenContent -match 'SeDenyInteractiveLogonRight') {{
                    $results.warnings += "VERIFIED: GptTmpl.inf contains SeDenyInteractiveLogonRight"
                }} else {{
                    $results.errors += "ERROR: GptTmpl.inf was written but does not contain expected content"
                }}
            }} else {{
                $results.errors += "ERROR: GptTmpl.inf was not created at $gptTmplPath"
            }}

            $results.configured += '{logon_name}'

            # Harden GPO permissions for tier-matched access control
            $tierAdminGroup = '{tier_admin_group}'

            # Harden base policy GPO permissions
            try {{
                $baseGpoObj = Get-GPO -Name '{base_name}' -ErrorAction Stop
                $baseGuid = $baseGpoObj.Id

                # Remove CREATOR OWNER permissions
                Set-GPPermission -Guid $baseGuid -TargetName 'S-1-3-0' -TargetType WellKnownGroup -PermissionLevel None -Replace -ErrorAction SilentlyContinue

                # Grant tier admin group full edit rights
                Set-GPPermission -Guid $baseGuid -TargetName $tierAdminGroup -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction SilentlyContinue

                # Ensure Authenticated Users can apply
                Set-GPPermission -Guid $baseGuid -TargetName 'Authenticated Users' -TargetType WellKnownGroup -PermissionLevel GpoApply -ErrorAction SilentlyContinue

                $results.warnings += "Hardened permissions on {base_name} for $tierAdminGroup"
            }} catch {{
                $results.warnings += "Could not harden {base_name} permissions: $($_.Exception.Message)"
            }}

            # Harden logon restrictions GPO permissions
            try {{
                $logonGpoObj = Get-GPO -Name '{logon_name}' -ErrorAction Stop
                $logonGuid = $logonGpoObj.Id

                # Remove CREATOR OWNER permissions
                Set-GPPermission -Guid $logonGuid -TargetName 'S-1-3-0' -TargetType WellKnownGroup -PermissionLevel None -Replace -ErrorAction SilentlyContinue

                # Grant tier admin group full edit rights
                Set-GPPermission -Guid $logonGuid -TargetName $tierAdminGroup -TargetType Group -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction SilentlyContinue

                # Ensure Authenticated Users can apply
                Set-GPPermission -Guid $logonGuid -TargetName 'Authenticated Users' -TargetType WellKnownGroup -PermissionLevel GpoApply -ErrorAction SilentlyContinue

                $results.warnings += "Hardened permissions on {logon_name} for $tierAdminGroup"
            }} catch {{
                $results.warnings += "Could not harden {logon_name} permissions: $($_.Exception.Message)"
            }}

        }} catch {{
            $results.errors += "Exception: $($_.Exception.Message)"
            $results.debug += "Full error: $_"
        }}

        $results | ConvertTo-Json -Depth 3 -Compress
        "#,
        base_name = base_name,
        logon_name = logon_name,
        tier = tier_name,
        target_ou = target_ou,
        deny_local = deny_local_str,
        deny_rdp = deny_rdp_str,
        deny_network = deny_network_str,
        apply_network_deny = if apply_network_deny { "$true" } else { "$false" },
        tier_admin_group = get_tier_admin_group(tier),
    );

    tracing::info!(tier = tier_name.as_str(), "Configuring GPOs for tier");

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to execute PowerShell");
            AppError::LdapError(format!("Failed to execute PowerShell: {}", e))
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    tracing::debug!(stdout = %stdout, "PowerShell output");

    if !stderr.is_empty() {
        tracing::warn!(stderr = %stderr, "PowerShell stderr");
        if !output.status.success() {
            result.add_error(format!("PowerShell error: {}", stderr));
        }
    }

    // Parse the JSON result
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Log debug info
        if let Some(debug) = json["debug"].as_array() {
            for item in debug {
                if let Some(s) = item.as_str() {
                    tracing::debug!(message = s, "GPO config debug");
                }
            }
        }

        if let Some(created) = json["created"].as_array() {
            for item in created {
                if let Some(s) = item.as_str() {
                    tracing::info!(gpo = s, "Created GPO");
                    result.gpos_created.push(s.to_string());
                }
            }
        }
        if let Some(configured) = json["configured"].as_array() {
            for item in configured {
                if let Some(s) = item.as_str() {
                    tracing::info!(gpo = s, "Configured GPO");
                    result.gpos_configured.push(s.to_string());
                }
            }
        }
        if let Some(linked) = json["linked"].as_array() {
            for item in linked {
                if let Some(s) = item.as_str() {
                    tracing::info!(gpo = s, "Linked GPO");
                    result.gpos_linked.push(s.to_string());
                }
            }
        }
        if let Some(errors) = json["errors"].as_array() {
            for item in errors {
                if let Some(s) = item.as_str() {
                    tracing::error!(error = s, "GPO configuration error");
                    result.add_error(s.to_string());
                }
            }
        }
        if let Some(warnings) = json["warnings"].as_array() {
            for item in warnings {
                if let Some(s) = item.as_str() {
                    tracing::warn!(warning = s, "GPO configuration warning");
                    result.add_warning(s.to_string());
                }
            }
        }
    } else {
        tracing::error!(stdout = %stdout, "Failed to parse PowerShell JSON output");
        result.add_error(format!("Failed to parse result: {}", stdout));
    }

    tracing::info!(
        tier = tier_name.as_str(),
        success = result.success,
        created = result.gpos_created.len(),
        configured = result.gpos_configured.len(),
        "GPO configuration complete"
    );

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
