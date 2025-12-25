//! Shared AD connection management
//!
//! This module provides a centralized connection manager for AD operations.
//! All command modules should use this instead of maintaining their own connection statics.

use super::AdConnection;
use once_cell::sync::Lazy;
use std::sync::Mutex;

/// Global AD connection - shared across all command modules
static AD_CONNECTION: Lazy<Mutex<Option<AdConnection>>> = Lazy::new(|| Mutex::new(None));

/// Get or create AD connection.
///
/// This function provides thread-safe access to a shared AD connection.
/// If no connection exists, it will attempt to create one.
///
/// # Returns
/// - `Ok(MutexGuard)` - A guard providing access to the connection
/// - `Err(String)` - If the lock is poisoned or connection fails
///
/// # Thread Safety
/// Uses a Mutex to ensure only one thread accesses the connection at a time.
/// If the mutex is poisoned (a thread panicked while holding it), we recover
/// by using the inner data.
pub fn get_connection() -> Result<std::sync::MutexGuard<'static, Option<AdConnection>>, String> {
    // First check if connection already exists (fast path)
    {
        let conn = AD_CONNECTION.lock().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "AD connection mutex was poisoned, recovering");
            e.into_inner()
        });
        if conn.is_some() {
            return Ok(conn);
        }
    } // Lock released here - don't hold during slow connect

    // Connect without holding the lock to avoid blocking other threads
    tracing::debug!("No existing AD connection, attempting to connect");
    let new_conn = AdConnection::connect().map_err(|e| {
        tracing::error!(error = %e, "Failed to connect to AD");
        format!("Failed to connect to AD: {}", e)
    })?;
    tracing::info!("AD connection established");

    // Re-acquire lock and store connection
    let mut conn = AD_CONNECTION.lock().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "AD connection mutex was poisoned, recovering");
        e.into_inner()
    });

    // Check if another thread connected while we were connecting
    if conn.is_none() {
        *conn = Some(new_conn);
    }

    Ok(conn)
}

/// Get the domain DN from the shared connection.
///
/// This is a convenience function that handles the common pattern of
/// getting the domain DN from the connection.
pub fn get_domain_dn() -> Result<String, String> {
    let conn = get_connection()?;
    match conn.as_ref() {
        Some(c) => Ok(c.domain_dn.clone()),
        None => Err("Not connected to Active Directory".to_string()),
    }
}

/// Clear the cached AD connection.
///
/// This forces a new connection on the next request.
/// Useful after reconnection requests or when credentials change.
pub fn clear_connection() {
    let mut conn = AD_CONNECTION.lock().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "AD connection mutex was poisoned, recovering");
        e.into_inner()
    });
    *conn = None;
    tracing::info!("AD connection cleared");
}
