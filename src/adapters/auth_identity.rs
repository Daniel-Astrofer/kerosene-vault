//! Authenticated mesh caller identity for day-vote / peer gossip.
//!
//! Does not touch TLS verify policy — hooks optional mTLS/SPIFFE peer node ids
//! when the transport layer supplies them; otherwise uses `X-Vault-Node-Id`
//! (must be a known peer) or falls back to this vault's local node id (kfe
//! self-vote path).

use std::collections::HashSet;

use crate::domain::DomainError;

/// Resolve the authenticated caller for mesh vote / gossip endpoints.
///
/// Priority:
/// 1. `mtls_peer_node_id` hook (when inbound mTLS maps cert → node id)
/// 2. `X-Vault-Node-Id` header when it is in `allowed_node_ids`
/// 3. `local_node_id` (kfe asking this vault to self-vote)
///
/// Optional body `claimed` must match the resolved identity (anti-spoof).
pub fn resolve_mesh_caller_identity(
    local_node_id: &str,
    allowed_node_ids: &HashSet<String>,
    header_node_id: Option<&str>,
    claimed: Option<&str>,
    mtls_peer_node_id: Option<&str>,
) -> Result<String, DomainError> {
    let identity = if let Some(peer) = mtls_peer_node_id
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !allowed_node_ids.contains(peer) && peer != local_node_id {
            return Err(DomainError::AuthRejected(format!(
                "mTLS peer identity {peer} is not a known mesh node"
            )));
        }
        peer.to_string()
    } else if let Some(hdr) = header_node_id.map(str::trim).filter(|s| !s.is_empty()) {
        if !allowed_node_ids.contains(hdr) && hdr != local_node_id {
            return Err(DomainError::AuthRejected(format!(
                "X-Vault-Node-Id {hdr} is not a known mesh node"
            )));
        }
        hdr.to_string()
    } else {
        local_node_id.to_string()
    };

    if let Some(raw) = claimed.map(str::trim).filter(|s| !s.is_empty()) {
        if raw != identity {
            return Err(DomainError::AuthRejected(format!(
                "voter {raw} does not match authenticated vault identity {identity}"
            )));
        }
    }
    Ok(identity)
}

/// Build the allowed voter / peer id set (local + seed peers).
pub fn mesh_allowed_node_ids(
    local_node_id: &str,
    seed_peer_ids: impl IntoIterator<Item = impl AsRef<str>>,
) -> HashSet<String> {
    let mut set = HashSet::new();
    set.insert(local_node_id.to_string());
    for id in seed_peer_ids {
        let id = id.as_ref().trim();
        if !id.is_empty() {
            set.insert(id.to_string());
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> HashSet<String> {
        mesh_allowed_node_ids("vault-1", ["vault-2", "vault-3"])
    }

    #[test]
    fn defaults_to_local_without_hooks() {
        assert_eq!(
            resolve_mesh_caller_identity("vault-1", &allowed(), None, None, None).unwrap(),
            "vault-1"
        );
    }

    #[test]
    fn accepts_known_peer_header() {
        assert_eq!(
            resolve_mesh_caller_identity("vault-1", &allowed(), Some("vault-2"), None, None)
                .unwrap(),
            "vault-2"
        );
    }

    #[test]
    fn rejects_unknown_header_spoof() {
        let err = resolve_mesh_caller_identity(
            "vault-1",
            &allowed(),
            Some("vault-evil"),
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, DomainError::AuthRejected(_)));
    }

    #[test]
    fn mtls_hook_wins_over_header() {
        assert_eq!(
            resolve_mesh_caller_identity(
                "vault-1",
                &allowed(),
                Some("vault-2"),
                None,
                Some("vault-3"),
            )
            .unwrap(),
            "vault-3"
        );
    }

    #[test]
    fn rejects_claimed_mismatch() {
        let err = resolve_mesh_caller_identity(
            "vault-1",
            &allowed(),
            None,
            Some("vault-2"),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, DomainError::AuthRejected(_)));
        assert!(err.to_string().contains("does not match"));
    }
}
