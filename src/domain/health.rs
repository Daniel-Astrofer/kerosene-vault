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
    pub attestation_mode: String,
    pub peer_count: usize,
}

impl NodeHealth {
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"node_id":"{}","status":"{}","attestation_mode":"{}","peer_count":{}}}"#,
            self.node_id,
            self.status.as_str(),
            self.attestation_mode,
            self.peer_count
        )
    }
}
