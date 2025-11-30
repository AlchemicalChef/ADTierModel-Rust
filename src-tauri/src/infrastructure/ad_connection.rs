//! Active Directory connection using Windows ADSI
//!
//! This module provides connection to Active Directory using the current
//! Windows user's credentials via ADSI (Active Directory Service Interfaces).

use crate::domain::DomainInfo;
use crate::error::{AppError, AppResult};

#[cfg(windows)]
use windows::{
    core::{BSTR, PCWSTR, VARIANT},
    Win32::Networking::ActiveDirectory::*,
    Win32::System::Com::*,
    Win32::System::Ole::*,
    Win32::System::Variant::*,
};

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;

/// Active Directory connection handle
pub struct AdConnection {
    pub domain_dn: String,
    pub dns_root: String,
    pub netbios_name: String,
    #[cfg(windows)]
    _com_initialized: bool,
}

impl AdConnection {
    /// Connect to Active Directory using current Windows credentials
    #[cfg(windows)]
    pub fn connect() -> AppResult<Self> {
        unsafe {
            // Initialize COM
            CoInitializeEx(None, COINIT_APARTMENTTHREADED)
                .map_err(|e| AppError::WindowsError(format!("COM initialization failed: {}", e)))?;

            // Connect to RootDSE to get domain info
            let root_dse_path = BSTR::from("LDAP://RootDSE");
            let mut root_dse: Option<IADs> = None;

            ADsOpenObject(
                PCWSTR(root_dse_path.as_ptr()),
                PCWSTR::null(),  // Use current credentials
                PCWSTR::null(),
                ADS_SECURE_AUTHENTICATION.0 as u32,
                &IADs::IID,
                &mut root_dse as *mut _ as *mut *mut std::ffi::c_void,
            )
            .map_err(|e| AppError::AuthenticationFailed(format!("Failed to connect to AD: {}", e)))?;

            let root_dse = root_dse.ok_or_else(|| {
                AppError::NotConnected
            })?;

            // Get defaultNamingContext (domain DN)
            let domain_dn = Self::get_ads_property(&root_dse, "defaultNamingContext")?;

            // Get dnsHostName or construct from domain DN
            let dns_root = Self::domain_dn_to_dns(&domain_dn);

            // Get NetBIOS name from configuration partition
            let netbios_name = Self::get_netbios_name(&domain_dn).unwrap_or_else(|_| {
                // Fallback: extract from domain DN
                domain_dn
                    .split(',')
                    .find(|s| s.starts_with("DC="))
                    .map(|s| s.trim_start_matches("DC=").to_uppercase())
                    .unwrap_or_else(|| "UNKNOWN".to_string())
            });

            Ok(Self {
                domain_dn,
                dns_root,
                netbios_name,
                _com_initialized: true,
            })
        }
    }

    /// Non-Windows fallback - returns error
    #[cfg(not(windows))]
    pub fn connect() -> AppResult<Self> {
        Err(AppError::NotConnected)
    }

    /// Get a property from an IADs object
    #[cfg(windows)]
    unsafe fn get_ads_property(ads: &IADs, property: &str) -> AppResult<String> {
        let prop_name = BSTR::from(property);
        let value = ads.Get(PCWSTR(prop_name.as_ptr()))
            .map_err(|e| AppError::LdapError(format!("Failed to get {}: {}", property, e)))?;

        Self::variant_to_string(&value)
    }

    /// Convert VARIANT to String
    #[cfg(windows)]
    unsafe fn variant_to_string(var: &VARIANT) -> AppResult<String> {
        let vt = var.Anonymous.Anonymous.vt;

        if vt == VT_BSTR {
            let bstr = &var.Anonymous.Anonymous.Anonymous.bstrVal;
            let len = SysStringLen(*bstr) as usize;
            if len == 0 {
                return Ok(String::new());
            }
            let slice = std::slice::from_raw_parts(bstr.0, len);
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
    #[cfg(windows)]
    unsafe fn get_netbios_name(domain_dn: &str) -> AppResult<String> {
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
            ADS_SECURE_AUTHENTICATION.0 as u32,
            &IDirectorySearch::IID,
            &mut search as *mut _ as *mut *mut std::ffi::c_void,
        )
        .map_err(|e| AppError::LdapError(format!("Failed to open config partition: {}", e)))?;

        let search = search.ok_or(AppError::LdapError("Search interface not available".to_string()))?;

        // Search for the partition with matching nCName
        let filter = BSTR::from(format!("(&(objectClass=crossRef)(nCName={}))", domain_dn).as_str());
        let attrs: [PCWSTR; 1] = [PCWSTR(BSTR::from("nETBIOSName").as_ptr())];

        let mut search_handle: ADS_SEARCH_HANDLE = std::ptr::null_mut();
        search.ExecuteSearch(
            PCWSTR(filter.as_ptr()),
            Some(&attrs as *const _ as *mut PCWSTR),
            1,
            &mut search_handle,
        )
        .map_err(|e| AppError::LdapError(format!("Search failed: {}", e)))?;

        // Get first row
        if search.GetFirstRow(search_handle).is_ok() {
            let mut column: ADS_SEARCH_COLUMN = std::mem::zeroed();
            let attr_name = BSTR::from("nETBIOSName");

            if search.GetColumn(search_handle, PCWSTR(attr_name.as_ptr()), &mut column).is_ok() {
                if !column.pADsValues.is_null() && column.dwNumValues > 0 {
                    let value = &*column.pADsValues;
                    if value.dwType == ADSTYPE_CASE_IGNORE_STRING.0 as u32
                        || value.dwType == ADSTYPE_DN_STRING.0 as u32 {
                        let ptr = value.Anonymous.CaseIgnoreString.0;
                        if !ptr.is_null() {
                            let len = (0..).take_while(|&i| *ptr.add(i) != 0).count();
                            let slice = std::slice::from_raw_parts(ptr, len);
                            let result = String::from_utf16_lossy(slice);
                            search.FreeColumn(&mut column).ok();
                            search.CloseSearchHandle(search_handle).ok();
                            return Ok(result);
                        }
                    }
                }
                search.FreeColumn(&mut column).ok();
            }
        }

        search.CloseSearchHandle(search_handle).ok();
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

#[cfg(windows)]
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
    #[cfg(windows)]
    {
        AdConnection::connect().is_ok()
    }
    #[cfg(not(windows))]
    {
        false
    }
}
