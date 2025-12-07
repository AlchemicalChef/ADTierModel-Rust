//! Active Directory connection using Windows ADSI
//!
//! This module provides connection to Active Directory using the current
//! Windows user's credentials via ADSI (Active Directory Service Interfaces).

use crate::domain::DomainInfo;
use crate::error::{AppError, AppResult};
use super::ensure_com_initialized;
use windows::{
    core::{BSTR, Interface, PCWSTR},
    Win32::Foundation::SysStringLen,
    Win32::Networking::ActiveDirectory::*,
    Win32::System::Com::CoUninitialize,
    Win32::System::Variant::*,
};
use std::ffi::OsString;

use std::os::windows::ffi::OsStringExt;

/// Active Directory connection handle
pub struct AdConnection {
    pub domain_dn: String,
    pub dns_root: String,
    pub netbios_name: String,

    _com_initialized: bool,
}

impl AdConnection {
    /// Connect to Active Directory using current Windows credentials

    pub fn connect() -> AppResult<Self> {
        tracing::info!("Attempting to connect to Active Directory");
        unsafe {
            // Initialize COM using centralized helper
            tracing::debug!("Initializing COM");
            ensure_com_initialized()?;

            // Connect to RootDSE to get domain info
            tracing::debug!("Connecting to RootDSE");
            let root_dse_path = BSTR::from("LDAP://RootDSE");
            let mut root_dse: Option<IADs> = None;

            ADsOpenObject(
                PCWSTR(root_dse_path.as_ptr()),
                PCWSTR::null(),  // Use current credentials
                PCWSTR::null(),
                ADS_SECURE_AUTHENTICATION,
                &<IADs as Interface>::IID,
                &mut root_dse as *mut _ as *mut *mut std::ffi::c_void,
            )
            .map_err(|e| {
                tracing::error!("Failed to connect to AD: {}", e);
                AppError::AuthenticationFailed(format!("Failed to connect to AD: {}", e))
            })?;

            let root_dse = root_dse.ok_or_else(|| {
                tracing::error!("RootDSE connection returned null");
                AppError::NotConnected
            })?;

            // Get defaultNamingContext (domain DN)
            let domain_dn = Self::get_ads_property(&root_dse, "defaultNamingContext")?;
            tracing::debug!("Retrieved domain DN: {}", domain_dn);

            // Get dnsHostName or construct from domain DN
            let dns_root = Self::domain_dn_to_dns(&domain_dn);
            tracing::debug!("DNS root: {}", dns_root);

            // Get NetBIOS name from configuration partition
            let netbios_name = Self::get_netbios_name(&domain_dn).unwrap_or_else(|e| {
                tracing::warn!("Failed to get NetBIOS name from config: {}, using fallback", e);
                // Fallback: extract from domain DN
                domain_dn
                    .split(',')
                    .find(|s| s.starts_with("DC="))
                    .map(|s| s.trim_start_matches("DC=").to_uppercase())
                    .unwrap_or_else(|| "UNKNOWN".to_string())
            });
            tracing::debug!("NetBIOS name: {}", netbios_name);

            tracing::info!("Successfully connected to AD domain: {} ({})", dns_root, netbios_name);
            Ok(Self {
                domain_dn,
                dns_root,
                netbios_name,
                _com_initialized: true,
            })
        }
    }

    /// Get a property from an IADs object

    unsafe fn get_ads_property(ads: &IADs, property: &str) -> AppResult<String> {
        tracing::debug!("Getting AD property: {}", property);
        let prop_name = BSTR::from(property);
        let value = ads.Get(&prop_name)
            .map_err(|e| {
                tracing::error!("Failed to get property {}: {}", property, e);
                AppError::LdapError(format!("Failed to get {}: {}", property, e))
            })?;

        Self::variant_to_string(&value)
    }

    /// Convert VARIANT to String

    unsafe fn variant_to_string(var: &VARIANT) -> AppResult<String> {
        let vt = var.Anonymous.Anonymous.vt;

        if vt == VT_BSTR {
            let bstr = &var.Anonymous.Anonymous.Anonymous.bstrVal;
            let len = SysStringLen(&**bstr) as usize;
            if len == 0 {
                return Ok(String::new());
            }
            let slice = std::slice::from_raw_parts((**bstr).as_ptr(), len);
            let os_string = OsString::from_wide(slice);
            os_string.into_string()
                .map_err(|_| AppError::LdapError("Invalid UTF-16 string".to_string()))
        } else if vt == VT_I4 {
            Ok(var.Anonymous.Anonymous.Anonymous.lVal.to_string())
        } else if vt == VT_BOOL {
            let b = var.Anonymous.Anonymous.Anonymous.boolVal;
            Ok(if b.0 != 0 { "TRUE" } else { "FALSE" }.to_string())
        } else {
            Ok(String::new())
        }
    }

    /// Convert domain DN to DNS name
    fn domain_dn_to_dns(dn: &str) -> String {
        dn.split(',')
            .filter(|s| s.starts_with("DC="))
            .map(|s| s.trim_start_matches("DC="))
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Get NetBIOS name from AD configuration

    unsafe fn get_netbios_name(domain_dn: &str) -> AppResult<String> {
        tracing::debug!("Querying NetBIOS name from configuration partition");
        // Query the Partitions container in the Configuration NC
        let config_path = format!(
            "LDAP://CN=Partitions,CN=Configuration,{}",
            domain_dn
        );
        let config_bstr = BSTR::from(config_path.as_str());

        let mut search: Option<IDirectorySearch> = None;
        ADsOpenObject(
            PCWSTR(config_bstr.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            ADS_SECURE_AUTHENTICATION,
            &<IDirectorySearch as Interface>::IID,
            &mut search as *mut _ as *mut *mut std::ffi::c_void,
        )
        .map_err(|e| {
            tracing::error!("Failed to open config partition: {}", e);
            AppError::LdapError(format!("Failed to open config partition: {}", e))
        })?;

        let search = search.ok_or_else(|| {
            tracing::error!("Search interface not available for config partition");
            AppError::LdapError("Search interface not available".to_string())
        })?;

        // Search for the partition with matching nCName
        // Escape domain_dn to prevent LDAP filter injection
        let filter = BSTR::from(format!(
            "(&(objectClass=crossRef)(nCName={}))",
            super::ad_search::escape_ldap_filter(domain_dn)
        ).as_str());
        // Keep BSTR alive for the duration of the search
        let attr_name_bstr = BSTR::from("nETBIOSName");
        let attrs: [PCWSTR; 1] = [PCWSTR(attr_name_bstr.as_ptr())];

        let search_handle = search.ExecuteSearch(
            PCWSTR(filter.as_ptr()),
            attrs.as_ptr(),
            1,
        )
        .map_err(|e| {
            tracing::error!("NetBIOS name search failed: {}", e);
            AppError::LdapError(format!("Search failed: {}", e))
        })?;

        // Get first row
        if search.GetFirstRow(search_handle).is_ok() {
            let mut column: ADS_SEARCH_COLUMN = std::mem::zeroed();
            let attr_name = BSTR::from("nETBIOSName");

            if search.GetColumn(search_handle, PCWSTR(attr_name.as_ptr()), &mut column).is_ok() {
                if !column.pADsValues.is_null() && column.dwNumValues > 0 {
                    let value = &*column.pADsValues;
                    if value.dwType == ADSTYPE_CASE_IGNORE_STRING
                        || value.dwType == ADSTYPE_DN_STRING {
                        let ptr = value.Anonymous.CaseIgnoreString;
                        if !ptr.is_null() {
                            let len = (0..).take_while(|&i| *ptr.add(i) != 0).count();
                            let slice = std::slice::from_raw_parts(ptr, len);
                            let result = String::from_utf16_lossy(slice);
                            search.FreeColumn(&mut column).ok();
                            search.CloseSearchHandle(search_handle).ok();
                            tracing::debug!("Found NetBIOS name: {}", result);
                            return Ok(result);
                        }
                    }
                }
                search.FreeColumn(&mut column).ok();
            }
        }

        search.CloseSearchHandle(search_handle).ok();
        tracing::warn!("NetBIOS name not found in configuration partition");
        Err(AppError::LdapError("NetBIOS name not found".to_string()))
    }

    /// Get domain info as a struct
    pub fn get_domain_info(&self) -> DomainInfo {
        DomainInfo {
            domain_dn: self.domain_dn.clone(),
            dns_root: self.dns_root.clone(),
            netbios_name: self.netbios_name.clone(),
            connected: true,
        }
    }
}
impl Drop for AdConnection {
    fn drop(&mut self) {
        if self._com_initialized {
            unsafe {
                CoUninitialize();
            }
        }
    }
}

/// Check if running on Windows and can connect to AD
pub fn is_ad_available() -> bool {
    AdConnection::connect().is_ok()
}
