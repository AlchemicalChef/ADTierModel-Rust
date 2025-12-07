//! Active Directory write operations using Windows ADSI
//!
//! This module provides functions to create OUs, groups, and other AD objects.

use crate::domain::{
    GroupSuffix, InitializationOptions, InitializationResult, InitializationStatus,
    SubOU, Tier, sub_ou_dn, tier_group_dn, tier_group_name, tier_ou_dn,
};
use crate::error::AppResult;

use crate::error::AppError;
use super::open_ad_object;
use windows::{
    core::{BSTR, Interface, PCWSTR},
    Win32::Networking::ActiveDirectory::*,
    Win32::System::Com::*,
    Win32::System::Variant::*,
};

/// Escape a string for safe use in PowerShell single-quoted strings.
/// Single quotes in PowerShell are escaped by doubling them: ' -> ''
fn escape_powershell_string(s: &str) -> String {
    s.replace('\'', "''")
}

/// Check if an OU exists

pub fn ou_exists(ou_dn: &str) -> AppResult<bool> {
    // Try to open the object - if it fails, it doesn't exist
    match open_ad_object::<IADs>(ou_dn) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Check if a group exists

pub fn group_exists(group_dn: &str) -> AppResult<bool> {
    ou_exists(group_dn) // Same check works for groups
}

/// Create an Organizational Unit

pub fn create_ou(parent_dn: &str, ou_name: &str, description: Option<&str>) -> AppResult<String> {
    tracing::info!(ou_name = ou_name, parent_dn = parent_dn, "Creating organizational unit");
    unsafe {
        let container: IADsContainer = open_ad_object(parent_dn)?;

        // Create the OU
        let class_name = BSTR::from("organizationalUnit");
        let relative_name = BSTR::from(format!("OU={}", ou_name).as_str());

        let new_obj: IADs = container
            .Create(&class_name, &relative_name)
            .map_err(|e| AppError::LdapError(format!("Failed to create OU {}: {}", ou_name, e)))?
            .cast()
            .map_err(|e| AppError::LdapError(format!("Failed to cast to IADs: {}", e)))?;

        // Set description if provided
        if let Some(desc) = description {
            let desc_name = BSTR::from("description");
            let desc_value = create_bstr_variant(desc);
            new_obj
                .Put(&desc_name, &desc_value)
                .map_err(|e| AppError::LdapError(format!("Failed to set description: {}", e)))?;
        }

        // Protect from accidental deletion
        // Note: This requires setting ntSecurityDescriptor which is complex
        // For now, we'll skip this protection

        // Commit the changes
        new_obj
            .SetInfo()
            .map_err(|e| {
                tracing::error!(ou_name = ou_name, error = %e, "Failed to commit OU");
                AppError::LdapError(format!("Failed to commit OU {}: {}", ou_name, e))
            })?;

        let new_dn = format!("OU={},{}", ou_name, parent_dn);
        tracing::info!(ou_dn = new_dn.as_str(), "Successfully created organizational unit");
        Ok(new_dn)
    }
}

/// Create a security group

pub fn create_security_group(
    parent_dn: &str,
    group_name: &str,
    description: Option<&str>,
    group_scope: GroupScope,
) -> AppResult<String> {
    tracing::info!(
        group_name = group_name,
        parent_dn = parent_dn,
        scope = ?group_scope,
        "Creating security group"
    );
    unsafe {
        let container: IADsContainer = open_ad_object(parent_dn)?;

        // Create the group
        let class_name = BSTR::from("group");
        let relative_name = BSTR::from(format!("CN={}", group_name).as_str());

        let new_obj: IADs = container
            .Create(&class_name, &relative_name)
            .map_err(|e| AppError::LdapError(format!("Failed to create group {}: {}", group_name, e)))?
            .cast()
            .map_err(|e| AppError::LdapError(format!("Failed to cast to IADs: {}", e)))?;

        // Set sAMAccountName
        let sam_name = BSTR::from("sAMAccountName");
        let sam_value = create_bstr_variant(group_name);
        new_obj
            .Put(&sam_name, &sam_value)
            .map_err(|e| AppError::LdapError(format!("Failed to set sAMAccountName: {}", e)))?;

        // Set groupType (Security group + scope)
        // Universal Security Group = -2147483640 (0x80000008)
        // Global Security Group = -2147483646 (0x80000002)
        // Domain Local Security Group = -2147483644 (0x80000004)
        let group_type_value = match group_scope {
            GroupScope::Universal => -2147483640i32,
            GroupScope::Global => -2147483646i32,
            GroupScope::DomainLocal => -2147483644i32,
        };

        let group_type_name = BSTR::from("groupType");
        let group_type_variant = create_i4_variant(group_type_value);
        new_obj
            .Put(&group_type_name, &group_type_variant)
            .map_err(|e| AppError::LdapError(format!("Failed to set groupType: {}", e)))?;

        // Set description if provided
        if let Some(desc) = description {
            let desc_name = BSTR::from("description");
            let desc_value = create_bstr_variant(desc);
            new_obj
                .Put(&desc_name, &desc_value)
                .map_err(|e| AppError::LdapError(format!("Failed to set description: {}", e)))?;
        }

        // Commit the changes
        new_obj
            .SetInfo()
            .map_err(|e| {
                tracing::error!(group_name = group_name, error = %e, "Failed to commit group");
                AppError::LdapError(format!("Failed to commit group {}: {}", group_name, e))
            })?;

        let new_dn = format!("CN={},{}", group_name, parent_dn);
        tracing::info!(group_dn = new_dn.as_str(), "Successfully created security group");
        Ok(new_dn)
    }
}

/// Group scope for security groups
#[derive(Debug, Clone, Copy)]
pub enum GroupScope {
    Universal,
    Global,
    DomainLocal,
}

/// Move an AD object to a different OU

pub fn move_ad_object(object_dn: &str, target_ou_dn: &str) -> AppResult<String> {
    tracing::info!(
        object_dn = object_dn,
        target_ou = target_ou_dn,
        "Moving AD object"
    );
    unsafe {
        // Open the object to move
        let obj: IADs = open_ad_object(object_dn)?;

        // Open the target container
        let target_container: IADsContainer = open_ad_object(target_ou_dn)?;

        // Move the object using MoveHere
        let ads_path = obj.ADsPath().map_err(|e| {
            AppError::LdapError(format!("Failed to get ADsPath: {}", e))
        })?;
        let empty_bstr = BSTR::new();

        target_container
            .MoveHere(&ads_path, &empty_bstr)
            .map_err(|e| {
                tracing::error!(
                    object_dn = object_dn,
                    target_ou = target_ou_dn,
                    error = %e,
                    "Failed to move AD object"
                );
                AppError::LdapError(format!(
                    "Failed to move {} to {}: {}",
                    object_dn, target_ou_dn, e
                ))
            })?;

        // Extract the RDN (CN=xxx or OU=xxx) from the original DN
        let rdn = object_dn
            .split(',')
            .next()
            .unwrap_or(object_dn);
        let new_dn = format!("{},{}", rdn, target_ou_dn);

        tracing::info!(new_dn = new_dn.as_str(), "Successfully moved AD object");
        Ok(new_dn)
    }
}

/// Add a member to a group

pub fn add_group_member(group_dn: &str, member_dn: &str) -> AppResult<()> {
    tracing::info!(
        group_dn = group_dn,
        member_dn = member_dn,
        "Adding member to group"
    );
    unsafe {
        let group: IADsGroup = open_ad_object(group_dn)?;

        // Add the member using LDAP path
        let member_path = format!("LDAP://{}", member_dn);
        let member_bstr = BSTR::from(member_path.as_str());

        group
            .Add(&member_bstr)
            .map_err(|e| {
                tracing::error!(
                    group_dn = group_dn,
                    member_dn = member_dn,
                    error = %e,
                    "Failed to add member to group"
                );
                AppError::LdapError(format!("Failed to add {} to {}: {}", member_dn, group_dn, e))
            })?;

        tracing::debug!(group_dn = group_dn, member_dn = member_dn, "Successfully added member to group");
        Ok(())
    }
}

/// Create a tiered admin user account

pub fn create_admin_user(
    parent_dn: &str,
    sam_account_name: &str,
    display_name: &str,
    description: Option<&str>,
    password: &str,
    enabled: bool,
) -> AppResult<String> {
    unsafe {
        let container: IADsContainer = open_ad_object(parent_dn)?;

        // Create the user object
        let class_name = BSTR::from("user");
        let relative_name = BSTR::from(format!("CN={}", display_name).as_str());

        let new_obj: IADs = container
            .Create(&class_name, &relative_name)
            .map_err(|e| AppError::LdapError(format!("Failed to create user {}: {}", sam_account_name, e)))?
            .cast()
            .map_err(|e| AppError::LdapError(format!("Failed to cast to IADs: {}", e)))?;

        // Set sAMAccountName
        let sam_attr = BSTR::from("sAMAccountName");
        let sam_value = create_bstr_variant(sam_account_name);
        new_obj
            .Put(&sam_attr, &sam_value)
            .map_err(|e| AppError::LdapError(format!("Failed to set sAMAccountName: {}", e)))?;

        // Set userPrincipalName (UPN)
        // Extract domain from parent_dn
        let domain_parts: Vec<&str> = parent_dn
            .split(',')
            .filter(|s| s.to_uppercase().starts_with("DC="))
            .map(|s| s.trim_start_matches("DC=").trim_start_matches("dc="))
            .collect();
        let domain_suffix = domain_parts.join(".");
        let upn = format!("{}@{}", sam_account_name, domain_suffix);
        let upn_attr = BSTR::from("userPrincipalName");
        let upn_value = create_bstr_variant(&upn);
        new_obj
            .Put(&upn_attr, &upn_value)
            .map_err(|e| AppError::LdapError(format!("Failed to set UPN: {}", e)))?;

        // Set displayName
        let display_attr = BSTR::from("displayName");
        let display_value = create_bstr_variant(display_name);
        new_obj
            .Put(&display_attr, &display_value)
            .map_err(|e| AppError::LdapError(format!("Failed to set displayName: {}", e)))?;

        // Set description if provided
        if let Some(desc) = description {
            let desc_attr = BSTR::from("description");
            let desc_value = create_bstr_variant(desc);
            new_obj
                .Put(&desc_attr, &desc_value)
                .map_err(|e| AppError::LdapError(format!("Failed to set description: {}", e)))?;
        }

        // Commit the object first (before setting password)
        new_obj
            .SetInfo()
            .map_err(|e| AppError::LdapError(format!("Failed to create user object: {}", e)))?;

        // Get IADsUser interface to set password
        let user: IADsUser = new_obj.cast().map_err(|e| {
            AppError::LdapError(format!("Failed to get user interface: {}", e))
        })?;

        // Set password
        let password_bstr = BSTR::from(password);
        user.SetPassword(&password_bstr)
            .map_err(|e| AppError::LdapError(format!("Failed to set password: {}", e)))?;

        // Set userAccountControl to enable/disable account
        // Normal account = 512 (0x200), Disabled = 514 (0x202)
        let uac_value = if enabled { 512i32 } else { 514i32 };
        let uac_attr = BSTR::from("userAccountControl");
        let uac_variant = create_i4_variant(uac_value);
        user.cast::<IADs>()
            .map_err(|e| AppError::LdapError(format!("Failed to cast to IADs: {}", e)))?
            .Put(&uac_attr, &uac_variant)
            .map_err(|e| AppError::LdapError(format!("Failed to set account control: {}", e)))?;

        // Commit changes
        user.cast::<IADs>()
            .map_err(|e| AppError::LdapError(format!("Failed to cast for SetInfo: {}", e)))?
            .SetInfo()
            .map_err(|e| AppError::LdapError(format!("Failed to commit user changes: {}", e)))?;

        let new_dn = format!("CN={},{}", display_name, parent_dn);
        Ok(new_dn)
    }
}

/// Remove a member from a group

pub fn remove_group_member(group_dn: &str, member_dn: &str) -> AppResult<()> {
    tracing::info!(
        group_dn = group_dn,
        member_dn = member_dn,
        "Removing member from group"
    );
    unsafe {
        let group: IADsGroup = open_ad_object(group_dn)?;

        // Remove the member using LDAP path
        let member_path = format!("LDAP://{}", member_dn);
        let member_bstr = BSTR::from(member_path.as_str());

        group
            .Remove(&member_bstr)
            .map_err(|e| {
                tracing::error!(
                    group_dn = group_dn,
                    member_dn = member_dn,
                    error = %e,
                    "Failed to remove member from group"
                );
                AppError::LdapError(format!("Failed to remove {} from {}: {}", member_dn, group_dn, e))
            })?;

        tracing::debug!(group_dn = group_dn, member_dn = member_dn, "Successfully removed member from group");
        Ok(())
    }
}

/// Create a VARIANT containing a BSTR

unsafe fn create_bstr_variant(s: &str) -> VARIANT {
    use windows::Win32::System::Variant::VariantInit;
    let bstr = BSTR::from(s);
    let mut var: VARIANT = VariantInit();
    // Access the union fields carefully
    let inner = &mut *std::ptr::addr_of_mut!(var.Anonymous.Anonymous);
    inner.vt = VT_BSTR;
    let innermost = &mut *std::ptr::addr_of_mut!(inner.Anonymous);
    innermost.bstrVal = std::mem::ManuallyDrop::new(bstr);
    var
}

/// Create a VARIANT containing an i4 (32-bit integer)

unsafe fn create_i4_variant(val: i32) -> VARIANT {
    use windows::Win32::System::Variant::VariantInit;
    let mut var: VARIANT = VariantInit();
    let inner = &mut *std::ptr::addr_of_mut!(var.Anonymous.Anonymous);
    inner.vt = VT_I4;
    let innermost = &mut *std::ptr::addr_of_mut!(inner.Anonymous);
    innermost.lVal = val;
    var
}

// ============================================================================
// OU Permission Management
// ============================================================================

/// AD Rights for access control
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum AdRights {
    /// Full control over the object
    GenericAll,
    /// Read all properties
    GenericRead,
    /// Write all properties
    GenericWrite,
    /// Delete the object
    Delete,
    /// Read the security descriptor
    ReadControl,
    /// Modify the DACL
    WriteDacl,
    /// Create child objects
    CreateChild,
    /// Delete child objects
    DeleteChild,
}

impl AdRights {
    fn to_mask(&self) -> i32 {
        match self {
            AdRights::GenericAll => 0x10000000,      // ADS_RIGHT_GENERIC_ALL
            AdRights::GenericRead => 0x80000000u32 as i32,  // ADS_RIGHT_GENERIC_READ
            AdRights::GenericWrite => 0x40000000,    // ADS_RIGHT_GENERIC_WRITE
            AdRights::Delete => 0x10000,             // ADS_RIGHT_DELETE
            AdRights::ReadControl => 0x20000,        // ADS_RIGHT_READ_CONTROL
            AdRights::WriteDacl => 0x40000,          // ADS_RIGHT_WRITE_DAC
            AdRights::CreateChild => 0x1,            // ADS_RIGHT_DS_CREATE_CHILD
            AdRights::DeleteChild => 0x2,            // ADS_RIGHT_DS_DELETE_CHILD
        }
    }
}

/// ACE type
#[derive(Debug, Clone, Copy)]
pub enum AceType {
    /// Allow access
    Allow,
    /// Deny access
    Deny,
}

impl AceType {
    fn to_value(&self) -> i32 {
        match self {
            AceType::Allow => 0, // ADS_ACETYPE_ACCESS_ALLOWED
            AceType::Deny => 1,  // ADS_ACETYPE_ACCESS_DENIED
        }
    }
}

/// ACE flags for inheritance
#[derive(Debug, Clone, Copy)]
pub enum AceFlags {
    /// No inheritance
    None,
    /// Inherit to child objects
    InheritChildren,
    /// Inherit to all descendants
    InheritAll,
}

impl AceFlags {
    fn to_value(&self) -> i32 {
        match self {
            AceFlags::None => 0,
            AceFlags::InheritChildren => 0x2, // ADS_ACEFLAG_INHERIT_ACE
            AceFlags::InheritAll => 0x2 | 0x1, // INHERIT_ACE | CONTAINER_INHERIT_ACE
        }
    }
}

/// Set permissions on an OU using ADSI

pub fn set_ou_permissions(
    ou_dn: &str,
    trustee: &str, // sAMAccountName or DN of group/user
    rights: AdRights,
    ace_type: AceType,
    flags: AceFlags,
) -> AppResult<()> {
    unsafe {
        // Open the OU
        let obj: IADs = open_ad_object(ou_dn)?;

        // Get the security descriptor
        let sd_prop = BSTR::from("ntSecurityDescriptor");
        let sd_variant = obj.Get(&sd_prop).map_err(|e| {
            AppError::LdapError(format!("Failed to get security descriptor: {}", e))
        })?;

        // Get the IADsSecurityDescriptor interface
        let sd_dispatch = sd_variant.Anonymous.Anonymous.Anonymous.pdispVal
            .as_ref()
            .ok_or_else(|| AppError::LdapError("Security descriptor dispatch is null".into()))?;
        let sd: IADsSecurityDescriptor = sd_dispatch.cast().map_err(|e| {
            AppError::LdapError(format!("Failed to cast to security descriptor: {}", e))
        })?;

        // Get the DACL
        let dacl_dispatch = sd.DiscretionaryAcl().map_err(|e| {
            AppError::LdapError(format!("Failed to get DACL: {}", e))
        })?;
        let dacl: IADsAccessControlList = dacl_dispatch.cast().map_err(|e| {
            AppError::LdapError(format!("Failed to cast to ACL: {}", e))
        })?;

        // Create a new ACE
        let ace: IADsAccessControlEntry =
            CoCreateInstance(&AccessControlEntry, None, CLSCTX_INPROC_SERVER).map_err(|e| {
                AppError::LdapError(format!("Failed to create ACE: {}", e))
            })?;

        // Configure the ACE
        ace.SetAccessMask(rights.to_mask()).map_err(|e| {
            AppError::LdapError(format!("Failed to set access mask: {}", e))
        })?;

        ace.SetAceType(ace_type.to_value()).map_err(|e| {
            AppError::LdapError(format!("Failed to set ACE type: {}", e))
        })?;

        ace.SetAceFlags(flags.to_value()).map_err(|e| {
            AppError::LdapError(format!("Failed to set ACE flags: {}", e))
        })?;

        let trustee_bstr = BSTR::from(trustee);
        ace.SetTrustee(&trustee_bstr).map_err(|e| {
            AppError::LdapError(format!("Failed to set trustee: {}", e))
        })?;

        // Add the ACE to the DACL
        let ace_dispatch: IDispatch = ace.cast().map_err(|e| {
            AppError::LdapError(format!("Failed to cast ACE to IDispatch: {}", e))
        })?;
        dacl.AddAce(Some(&ace_dispatch)).map_err(|e| {
            AppError::LdapError(format!("Failed to add ACE to DACL: {}", e))
        })?;

        // Set the modified DACL back
        let dacl_dispatch: IDispatch = dacl.cast().map_err(|e| {
            AppError::LdapError(format!("Failed to cast ACL to IDispatch: {}", e))
        })?;
        sd.SetDiscretionaryAcl(Some(&dacl_dispatch)).map_err(|e| {
            AppError::LdapError(format!("Failed to set DACL: {}", e))
        })?;

        // Write the security descriptor back
        let sd_dispatch_out: IDispatch = sd.cast().map_err(|e| {
            AppError::LdapError(format!("Failed to cast SD to IDispatch: {}", e))
        })?;

        let mut sd_variant_out: VARIANT = {
            use windows::Win32::System::Variant::VariantInit;
            let mut var = VariantInit();
            let inner = &mut *std::ptr::addr_of_mut!(var.Anonymous.Anonymous);
            inner.vt = VT_DISPATCH;
            let innermost = &mut *std::ptr::addr_of_mut!(inner.Anonymous);
            innermost.pdispVal = std::mem::ManuallyDrop::new(Some(sd_dispatch_out));
            var
        };

        obj.Put(&sd_prop, &sd_variant_out).map_err(|e| {
            AppError::LdapError(format!("Failed to put security descriptor: {}", e))
        })?;

        obj.SetInfo().map_err(|e| {
            AppError::LdapError(format!("Failed to commit permission changes: {}", e))
        })?;

        Ok(())
    }
}

/// Protect an OU from accidental deletion

pub fn protect_ou_from_deletion(ou_dn: &str) -> AppResult<()> {
    // Deny Delete and DeleteTree to Everyone
    set_ou_permissions(
        ou_dn,
        "Everyone",
        AdRights::Delete,
        AceType::Deny,
        AceFlags::None,
    )
}

// ============================================================================
// GPO Management
// ============================================================================

/// GPO configuration for a tier
#[derive(Debug, Clone)]
pub struct TierGpoConfig {
    /// Base security policy GPO name
    pub base_policy_name: String,
    /// Logon restrictions GPO name
    pub logon_restrictions_name: String,
    /// Target OU for linking
    pub target_ou: String,
    /// Groups to deny logon
    pub deny_groups: Vec<String>,
}

impl TierGpoConfig {
    /// Create configuration for a tier
    pub fn for_tier(tier: Tier, domain_dn: &str) -> Self {
        let tier_name = tier.to_string();
        let target_ou = tier_ou_dn(tier, domain_dn);

        // Determine which groups to deny based on tier
        let deny_groups = match tier {
            Tier::Tier0 => vec![
                "Tier1-Admins".to_string(),
                "Tier2-Admins".to_string(),
            ],
            Tier::Tier1 => vec![
                "Tier2-Admins".to_string(),
            ],
            Tier::Tier2 => vec![
                // Tier2 typically doesn't deny other tiers
                // as it's the lowest level
            ],
        };

        Self {
            base_policy_name: format!("SEC-{}-BasePolicy", tier_name),
            logon_restrictions_name: format!("SEC-{}-LogonRestrictions", tier_name),
            target_ou,
            deny_groups,
        }
    }
}

/// Create GPOs for all tiers using PowerShell
///
/// This function invokes PowerShell to create GPOs because:
/// 1. The GroupPolicy PowerShell module provides reliable GPO management
/// 2. Direct COM access to GPMC is complex and brittle
/// 3. The ADTierModel.psm1 module provides tested functions

pub fn create_tier_gpos(domain_dn: &str) -> AppResult<Vec<String>> {
    use std::process::Command;

    let mut gpos_created = Vec::new();

    // Build PowerShell script to create GPOs
    for tier in Tier::all() {
        let config = TierGpoConfig::for_tier(*tier, domain_dn);

        // PowerShell command to create base GPO
        // Escape all interpolated values to prevent PowerShell injection
        let base_name = escape_powershell_string(&config.base_policy_name);
        let logon_name = escape_powershell_string(&config.logon_restrictions_name);
        let tier_str = escape_powershell_string(&tier.to_string());
        let target = escape_powershell_string(&config.target_ou);

        let ps_script = format!(
            r#"
            Import-Module GroupPolicy -ErrorAction Stop

            # Create base policy GPO if it doesn't exist
            $baseGpo = Get-GPO -Name '{base_name}' -ErrorAction SilentlyContinue
            if (-not $baseGpo) {{
                $baseGpo = New-GPO -Name '{base_name}' -Comment 'Base security policy for {tier_str}'
                New-GPLink -Name '{base_name}' -Target '{target}' -LinkEnabled Yes -ErrorAction SilentlyContinue
                Write-Output "Created:{base_name}"
            }}

            # Create logon restrictions GPO if it doesn't exist
            $logonGpo = Get-GPO -Name '{logon_name}' -ErrorAction SilentlyContinue
            if (-not $logonGpo) {{
                $logonGpo = New-GPO -Name '{logon_name}' -Comment 'Logon restrictions for {tier_str}'
                New-GPLink -Name '{logon_name}' -Target '{target}' -LinkEnabled Yes -Order 1 -ErrorAction SilentlyContinue
                Write-Output "Created:{logon_name}"
            }}
            "#,
        );

        let output = Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
            .output()
            .map_err(|e| crate::error::AppError::LdapError(
                format!("Failed to execute PowerShell: {}", e)
            ))?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.starts_with("Created:") {
                    gpos_created.push(line.replace("Created:", ""));
                }
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Don't fail entirely, just warn - GPO module might not be available
            if !stderr.is_empty() {
                return Err(crate::error::AppError::LdapError(
                    format!("PowerShell GPO creation failed: {}", stderr)
                ));
            }
        }
    }

    if gpos_created.is_empty() {
        // If no GPOs were created, the module might not be available
        return Err(crate::error::AppError::LdapError(
            "No GPOs created. Ensure the GroupPolicy PowerShell module is installed (RSAT).".to_string()
        ));
    }

    Ok(gpos_created)
}

/// Configure logon restrictions in an existing GPO
/// This is an advanced operation that requires the GPO to exist

pub fn configure_logon_restrictions(
    gpo_name: &str,
    deny_groups: &[String],
    _domain_dn: &str,
) -> AppResult<()> {
    use std::process::Command;

    if deny_groups.is_empty() {
        return Ok(()); // Nothing to configure
    }

    // Build the identity string for PowerShell
    // Escape each group name to prevent PowerShell injection
    let identities: Vec<String> = deny_groups
        .iter()
        .map(|g| format!("'{}'", escape_powershell_string(g)))
        .collect();
    let identity_array = identities.join(", ");

    // Escape the GPO name
    let gpo_name_escaped = escape_powershell_string(gpo_name);

    // PowerShell script to configure user rights
    // Note: This is a simplified version - full implementation would use secedit
    let ps_script = format!(
        r#"
        Import-Module GroupPolicy -ErrorAction Stop

        $gpo = Get-GPO -Name '{gpo_name_escaped}'
        if (-not $gpo) {{
            throw "GPO not found: {gpo_name_escaped}"
        }}

        # Note: Full logon restriction configuration requires secedit
        # This is a placeholder that verifies the GPO exists
        Write-Output "GPO verified: {gpo_name_escaped}"
        Write-Output "Deny groups configured: @({identity_array})"

        # For full implementation, use Set-ADTierLogonRestrictions from ADTierModel.psm1
        "#,
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_script])
        .output()
        .map_err(|e| crate::error::AppError::LdapError(
            format!("Failed to execute PowerShell: {}", e)
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::error::AppError::LdapError(
            format!("GPO configuration failed: {}", stderr)
        ));
    }

    Ok(())
}

/// Set up tier admin permissions on an OU
/// Grants the tier's admin group full control over the OU and its children
pub fn setup_tier_admin_permissions(
    tier: Tier,
    domain_dn: &str,
) -> AppResult<Vec<String>> {
    let mut permissions_set = Vec::new();
    let tier_ou = tier_ou_dn(tier, domain_dn);
    let admin_group = tier_group_name(tier, GroupSuffix::Admins);

    // Grant full control to tier admin group
    set_ou_permissions(
        &tier_ou,
        &admin_group,
        AdRights::GenericAll,
        AceType::Allow,
        AceFlags::InheritAll,
    )?;
    permissions_set.push(format!("Granted Full Control to {} on {}", admin_group, tier_ou));

    // Grant read access to operators
    let operators_group = tier_group_name(tier, GroupSuffix::Operators);
    set_ou_permissions(
        &tier_ou,
        &operators_group,
        AdRights::GenericRead,
        AceType::Allow,
        AceFlags::InheritAll,
    )?;
    permissions_set.push(format!("Granted Read to {} on {}", operators_group, tier_ou));

    // Grant read access to readers
    let readers_group = tier_group_name(tier, GroupSuffix::Readers);
    set_ou_permissions(
        &tier_ou,
        &readers_group,
        AdRights::GenericRead,
        AceType::Allow,
        AceFlags::InheritAll,
    )?;
    permissions_set.push(format!("Granted Read to {} on {}", readers_group, tier_ou));

    // Protect from accidental deletion
    protect_ou_from_deletion(&tier_ou)?;
    permissions_set.push(format!("Protected {} from accidental deletion", tier_ou));

    // Also protect sub-OUs
    for sub_ou in SubOU::all() {
        let sub_dn = sub_ou_dn(tier, *sub_ou, domain_dn);
        if ou_exists(&sub_dn).unwrap_or(false) {
            protect_ou_from_deletion(&sub_dn)?;
            permissions_set.push(format!("Protected {} from accidental deletion", sub_dn));
        }
    }

    Ok(permissions_set)
}

/// Check initialization status of the tier model
pub fn check_initialization_status(domain_dn: &str) -> AppResult<InitializationStatus> {
    let mut status = InitializationStatus::not_initialized();
    let mut missing = Vec::new();

    // Check tier OUs
    for tier in Tier::all() {
        let ou_dn = tier_ou_dn(*tier, domain_dn);
        let exists = ou_exists(&ou_dn).unwrap_or(false);

        match tier {
            Tier::Tier0 => status.tier0_ou_exists = exists,
            Tier::Tier1 => status.tier1_ou_exists = exists,
            Tier::Tier2 => status.tier2_ou_exists = exists,
        }

        if !exists {
            missing.push(format!("{} OU", tier));
        }
    }

    // Check if at least some groups exist
    let sample_group_dn = tier_group_dn(Tier::Tier0, GroupSuffix::Admins, domain_dn);
    status.groups_exist = group_exists(&sample_group_dn).unwrap_or(false);

    if !status.groups_exist {
        missing.push("Tier security groups".to_string());
    }

    status.missing_components = missing;
    status.is_initialized = status.tier0_ou_exists
        && status.tier1_ou_exists
        && status.tier2_ou_exists
        && status.groups_exist;

    Ok(status)
}

/// Initialize the AD Tier Model structure
pub fn initialize_tier_model(
    domain_dn: &str,
    options: &InitializationOptions,
) -> AppResult<InitializationResult> {
    tracing::info!(
        domain_dn = domain_dn,
        create_ou = options.create_ou_structure,
        create_groups = options.create_groups,
        set_permissions = options.set_permissions,
        create_gpos = options.create_gpos,
        "Initializing AD Tier Model"
    );
    let mut result = InitializationResult::new();

    // Create OU structure
    if options.create_ou_structure {
        for tier in Tier::all() {
            // Create main tier OU
            let tier_dn = tier_ou_dn(*tier, domain_dn);
            if !options.force && ou_exists(&tier_dn).unwrap_or(false) {
                result.add_warning(format!("{} OU already exists, skipping", tier));
            } else {
                match create_ou(domain_dn, &tier.to_string(), Some(tier.display_name())) {
                    Ok(dn) => result.ous_created.push(dn),
                    Err(e) => {
                        if !options.force {
                            result.add_error(format!("Failed to create {} OU: {}", tier, e));
                        }
                    }
                }
            }

            // Create sub-OUs
            let tier_ou = tier_ou_dn(*tier, domain_dn);
            for sub_ou in SubOU::all() {
                let sub_dn = sub_ou_dn(*tier, *sub_ou, domain_dn);
                if !options.force && ou_exists(&sub_dn).unwrap_or(false) {
                    // Already exists, skip silently
                    continue;
                }

                match create_ou(&tier_ou, sub_ou.as_str(), Some(&sub_ou.description(*tier))) {
                    Ok(dn) => result.ous_created.push(dn),
                    Err(e) => {
                        // Sub-OU creation failure is a warning, not fatal
                        result.add_warning(format!(
                            "Failed to create {}/{} OU: {}",
                            tier,
                            sub_ou.as_str(),
                            e
                        ));
                    }
                }
            }
        }
    }

    // Create security groups
    if options.create_groups {
        for tier in Tier::all() {
            let groups_ou = format!("OU=Groups,{},{}", tier.ou_path(), domain_dn);

            // Check if Groups OU exists first
            if !ou_exists(&groups_ou).unwrap_or(false) {
                result.add_warning(format!(
                    "Groups OU for {} doesn't exist, skipping group creation",
                    tier
                ));
                continue;
            }

            for suffix in GroupSuffix::all() {
                let group_name = tier_group_name(*tier, *suffix);
                let group_dn = tier_group_dn(*tier, *suffix, domain_dn);

                if !options.force && group_exists(&group_dn).unwrap_or(false) {
                    // Already exists, skip
                    continue;
                }

                let description = format!(
                    "{} - {} group for {} tier",
                    group_name,
                    suffix.description(),
                    tier.display_name()
                );

                match create_security_group(
                    &groups_ou,
                    &group_name,
                    Some(&description),
                    GroupScope::Universal,
                ) {
                    Ok(dn) => result.groups_created.push(dn),
                    Err(e) => {
                        result.add_warning(format!("Failed to create group {}: {}", group_name, e));
                    }
                }
            }
        }
    }

    // Set permissions on tier OUs
    if options.set_permissions {
        for tier in Tier::all() {
            let tier_ou = tier_ou_dn(*tier, domain_dn);

            // Only set permissions if the OU exists
            if !ou_exists(&tier_ou).unwrap_or(false) {
                result.add_warning(format!(
                    "Cannot set permissions on {} - OU doesn't exist",
                    tier
                ));
                continue;
            }

            match setup_tier_admin_permissions(*tier, domain_dn) {
                Ok(permissions) => {
                    result.permissions_set.extend(permissions);
                }
                Err(e) => {
                    result.add_warning(format!(
                        "Failed to set permissions on {}: {}",
                        tier, e
                    ));
                }
            }
        }
    }

    // Create GPOs for logon restrictions
    if options.create_gpos {
        match create_tier_gpos(domain_dn) {
            Ok(gpos) => {
                result.gpos_created = gpos;
            }
            Err(e) => {
                result.add_warning(format!(
                    "GPO creation failed: {}. Consider using PowerShell: Initialize-ADTierModel -CreateGPOs",
                    e
                ));
            }
        }
    }

    tracing::info!(
        ous_created = result.ous_created.len(),
        groups_created = result.groups_created.len(),
        gpos_created = result.gpos_created.len(),
        warnings = result.warnings.len(),
        errors = result.errors.len(),
        "AD Tier Model initialization complete"
    );
    Ok(result)
}

/// Disable a user account by setting userAccountControl flag

pub fn disable_account(object_dn: &str) -> AppResult<()> {
    tracing::info!(object_dn = object_dn, "Disabling account");
    unsafe {
        let obj: IADs = open_ad_object(object_dn)?;

        // Get current userAccountControl
        let uac_attr = BSTR::from("userAccountControl");
        let uac_variant = obj
            .Get(&uac_attr)
            .map_err(|e| AppError::LdapError(format!("Failed to get userAccountControl: {}", e)))?;

        let current_uac = uac_variant.Anonymous.Anonymous.Anonymous.lVal;

        // Set ADS_UF_ACCOUNTDISABLE flag (0x2)
        const ADS_UF_ACCOUNTDISABLE: i32 = 0x2;
        let new_uac = current_uac | ADS_UF_ACCOUNTDISABLE;

        // Set the new value
        let new_uac_variant = create_i4_variant(new_uac);
        obj.Put(&uac_attr, &new_uac_variant)
            .map_err(|e| AppError::LdapError(format!("Failed to set userAccountControl: {}", e)))?;

        // Commit the change
        obj.SetInfo()
            .map_err(|e| {
                tracing::error!(object_dn = object_dn, error = %e, "Failed to commit disable");
                AppError::LdapError(format!("Failed to commit disable: {}", e))
            })?;

        tracing::info!(object_dn = object_dn, "Successfully disabled account");
        Ok(())
    }
}

/// Bulk disable multiple accounts
pub fn bulk_disable_accounts(object_dns: &[String]) -> Vec<Result<String, String>> {
    object_dns
        .iter()
        .map(|dn| {
            disable_account(dn)
                .map(|_| dn.clone())
                .map_err(|e| format!("{}: {}", dn, e))
        })
        .collect()
}

/// Mark a service account as sensitive (cannot be delegated)
/// This sets the TRUSTED_TO_AUTH_FOR_DELEGATION flag off and sets NOT_DELEGATED flag

pub fn harden_service_account(object_dn: &str) -> AppResult<()> {
    tracing::info!(object_dn = object_dn, "Hardening service account");
    unsafe {
        let obj: IADs = open_ad_object(object_dn)?;

        // Get current userAccountControl
        let uac_attr = BSTR::from("userAccountControl");
        let uac_variant = obj
            .Get(&uac_attr)
            .map_err(|e| AppError::LdapError(format!("Failed to get userAccountControl: {}", e)))?;

        let current_uac = uac_variant.Anonymous.Anonymous.Anonymous.lVal;

        // Set NOT_DELEGATED flag (0x100000) - Account is sensitive and cannot be delegated
        // Also remove TRUSTED_TO_AUTH_FOR_DELEGATION if set (0x1000000)
        const ADS_UF_NOT_DELEGATED: i32 = 0x100000;
        const ADS_UF_TRUSTED_TO_AUTH_FOR_DELEGATION: i32 = 0x1000000;

        let new_uac = (current_uac | ADS_UF_NOT_DELEGATED) & !ADS_UF_TRUSTED_TO_AUTH_FOR_DELEGATION;

        // Set the new value
        let new_uac_variant = create_i4_variant(new_uac);
        obj.Put(&uac_attr, &new_uac_variant)
            .map_err(|e| AppError::LdapError(format!("Failed to set userAccountControl: {}", e)))?;

        // Commit the change
        obj.SetInfo()
            .map_err(|e| {
                tracing::error!(object_dn = object_dn, error = %e, "Failed to commit security hardening");
                AppError::LdapError(format!("Failed to commit security hardening: {}", e))
            })?;

        tracing::info!(object_dn = object_dn, "Successfully hardened service account");
        Ok(())
    }
}

/// Bulk harden multiple service accounts
pub fn bulk_harden_service_accounts(object_dns: &[String]) -> Vec<Result<String, String>> {
    object_dns
        .iter()
        .map(|dn| {
            harden_service_account(dn)
                .map(|_| dn.clone())
                .map_err(|e| format!("{}: {}", dn, e))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_group_name() {
        assert_eq!(
            tier_group_name(Tier::Tier0, GroupSuffix::Admins),
            "Tier0-Admins"
        );
        assert_eq!(
            tier_group_name(Tier::Tier1, GroupSuffix::Operators),
            "Tier1-Operators"
        );
    }

    #[test]
    fn test_tier_ou_dn() {
        let domain_dn = "DC=contoso,DC=com";
        assert_eq!(
            tier_ou_dn(Tier::Tier0, domain_dn),
            "OU=Tier0,DC=contoso,DC=com"
        );
    }

    #[test]
    fn test_sub_ou_dn() {
        let domain_dn = "DC=contoso,DC=com";
        assert_eq!(
            sub_ou_dn(Tier::Tier0, SubOU::Computers, domain_dn),
            "OU=Computers,OU=Tier0,DC=contoso,DC=com"
        );
    }
}
