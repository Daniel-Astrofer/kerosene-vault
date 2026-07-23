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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHealth {
    pub node_id: NodeId,
    pub status: HealthStatus,
    pub node_tier: String,
    pub attestation_mode: String,
    pub tee_available: bool,
    pub peer_count: usize,
}

impl NodeHealth {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"node_id":"{}","status":"{}","node_tier":"{}","attestation_mode":"{}","tee_available":{},"peer_count":{}}}"#,
            self.node_id,
            self.status.as_str(),
            self.node_tier,
            self.attestation_mode,
            self.tee_available,
            self.peer_count
        )
    }
}
