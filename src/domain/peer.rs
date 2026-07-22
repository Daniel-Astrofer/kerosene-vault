use std::fmt;

use crate::domain::DomainError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(raw: impl Into<String>) -> Result<Self, DomainError> {
        let id = raw.into().trim().to_string();
        if id.is_empty() || id.len() > 128 {
            return Err(DomainError::InvalidNodeId);
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub id: NodeId,
    pub endpoint: PeerEndpoint,
}
