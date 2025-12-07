pub mod ad_connection;
pub mod ad_search;
pub mod ad_write;
pub mod compliance_check;
pub mod endpoint_protection;
pub mod gpo_management;

pub use ad_connection::*;
pub use ad_search::*;
pub use ad_write::*;
pub use compliance_check::*;
pub use endpoint_protection::*;
pub use gpo_management::*;

// Common Windows AD helper functions

mod ad_helpers {
    use crate::error::{AppError, AppResult};
    use windows::{
        core::{Interface, BSTR, PCWSTR},
        Win32::Networking::ActiveDirectory::{ADsOpenObject, ADS_SECURE_AUTHENTICATION},
        Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED},
    };

    /// Ensure COM is initialized for the current thread.
    /// Safe to call multiple times - will return Ok if already initialized.
    pub fn ensure_com_initialized() -> AppResult<()> {
        unsafe {
            let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            let hr_code = hr.0 as u32;
            // S_OK (0) or S_FALSE (1) means success or already initialized
            if hr.is_ok() || hr_code == 0x00000001 {
                Ok(())
            } else if hr_code == 0x80010106 {
                // RPC_E_CHANGED_MODE - COM was initialized with different mode, but we can continue
                tracing::debug!("COM initialized with different threading model, continuing");
                Ok(())
            } else {
                Err(AppError::WindowsError(format!("COM initialization failed: 0x{:08X}", hr_code)))
            }
        }
    }

    /// Open an AD object with the specified COM interface.
    /// Handles COM initialization, path formatting, and error handling.
    pub fn open_ad_object<T: Interface>(dn: &str) -> AppResult<T> {
        ensure_com_initialized()?;
        unsafe {
            let ldap_path = format!("LDAP://{}", dn);
            let path_bstr = BSTR::from(ldap_path.as_str());
            let mut obj: Option<T> = None;

            ADsOpenObject(
                PCWSTR(path_bstr.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                ADS_SECURE_AUTHENTICATION,
                &T::IID,
                &mut obj as *mut _ as *mut *mut std::ffi::c_void,
            )
            .map_err(|e| AppError::LdapError(format!("Failed to open {}: {}", dn, e)))?;

            obj.ok_or_else(|| AppError::LdapError(format!("Object not found: {}", dn)))
        }
    }
}
pub use ad_helpers::{ensure_com_initialized, open_ad_object};
