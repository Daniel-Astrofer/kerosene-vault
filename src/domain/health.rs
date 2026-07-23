use crate::domain::NodeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Starting,
    Ready,
    Degraded,
}

impl HealthStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Degraded => "degraded",
        }
    }
}

/// Honesty signal for peer liveness — directory presence ≠ probed reachability.
/// Does not claim Tor mesh health; Tor probing is a separate Gate item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerReachability {
    /// No peers configured.
    None,
    /// Peers listed in directory only; TCP/Tor not probed.
    DirectoryOnly,
    /// Clearnet TCP probe attempted (optional cheap signal).
    Probed { reachable: usize, configured: usize },
}

impl PeerReachability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::DirectoryOnly => "directory_only",
            Self::Probed { .. } => "probed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHealth {
    pub node_id: NodeId,
    pub status: HealthStatus,
    pub node_tier: String,
    pub attestation_mode: String,
    pub tee_available: bool,
    pub peer_count: usize,
    /// Seated genesis / wire-DKG roster (SEV-priority); empty if unknown.
    pub genesis_roster: Vec<String>,
    /// Peer reachability honesty (not Tor-complete).
    pub peer_reachability: PeerReachability,
    /// When probed: how many peers accepted a cheap TCP connect (None if not probed).
    pub peers_reachable: Option<usize>,
}

impl NodeHealth {
    pub fn to_json(&self) -> String {
        let roster = self
            .genesis_roster
            .iter()
            .map(|id| format!(r#""{id}""#))
            .collect::<Vec<_>>()
            .join(",");
        let reachable = match self.peers_reachable {
            Some(n) => n.to_string(),
            None => "null".into(),
        };
        format!(
            r#"{{"node_id":"{}","status":"{}","node_tier":"{}","attestation_mode":"{}","tee_available":{},"peer_count":{},"genesis_roster":[{}],"peer_reachability":"{}","peers_reachable":{}}}"#,
            self.node_id,
            self.status.as_str(),
            self.node_tier,
            self.attestation_mode,
            self.tee_available,
            self.peer_count,
            roster,
            self.peer_reachability.as_str(),
            reachable
        )
    }
}
