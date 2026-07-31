//! Bitcoin network policy for vault destination validation (Lab P0: testnet3).

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Network};

use crate::domain::DomainError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    /// Bitcoin testnet3 (default for Lab P0).
    Testnet3,
    /// Mainnet — Production Gate only; not default.
    Mainnet,
}

impl BitcoinNetwork {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "testnet3" | "testnet" | "test" => Some(Self::Testnet3),
            "mainnet" | "bitcoin" | "main" => Some(Self::Mainnet),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Testnet3 => "testnet3",
            Self::Mainnet => "mainnet",
        }
    }

    pub fn to_bitcoin(self) -> Network {
        match self {
            Self::Testnet3 => Network::Testnet,
            Self::Mainnet => Network::Bitcoin,
        }
    }
}

/// Validate a destination string for the configured Bitcoin network.
///
/// Opaque lab labels (e.g. `ln-*`, `internal-*`, non-address placeholders) pass
/// through. Strings that parse as Bitcoin addresses must match the network:
/// on testnet3, `tb1…` and legacy testnet are accepted; `bc1…` / mainnet rejected.
pub fn validate_destination(network: BitcoinNetwork, destination: &str) -> Result<(), DomainError> {
    let dest = destination.trim();
    if dest.is_empty() {
        return Err(DomainError::InvalidIntent("empty destination".into()));
    }

    // Fast-path reject: explicit mainnet bech32 HRP on testnet3.
    if network == BitcoinNetwork::Testnet3 && (dest.starts_with("bc1") || dest.starts_with("BC1")) {
        return Err(DomainError::BitcoinNetworkMismatch(
            "mainnet bc1 address rejected on BITCOIN_NETWORK=testnet3".into(),
        ));
    }

    match dest.parse::<Address<NetworkUnchecked>>() {
        Ok(unchecked) => {
            let checked = unchecked.require_network(network.to_bitcoin()).map_err(|_| {
                DomainError::BitcoinNetworkMismatch(format!("address not valid for {}", network.as_str()))
            })?;
            let _ = checked;
            Ok(())
        }
        Err(_) => {
            // Not a parseable Bitcoin address — opaque lab / LN / internal tag.
            Ok(())
        }
    }
}

/// Resolve Intent destination to a scriptPubKey for PSBT binding.
/// Opaque lab tags cannot bind on-chain — callers must use a real address.
pub fn destination_script_pubkey(
    network: BitcoinNetwork,
    destination: &str,
) -> Result<bitcoin::ScriptBuf, DomainError> {
    validate_destination(network, destination)?;
    let dest = destination.trim();
    let unchecked = dest.parse::<Address<NetworkUnchecked>>().map_err(|_| {
        DomainError::InvalidIntent(
            "PSBT Intent bind requires a Bitcoin address destination (opaque lab tags cannot bind outputs)".into(),
        )
    })?;
    let checked = unchecked
        .require_network(network.to_bitcoin())
        .map_err(|_| DomainError::BitcoinNetworkMismatch(format!("address not valid for {}", network.as_str())))?;
    Ok(checked.script_pubkey())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testnet3_rejects_bc1_prefix() {
        let err =
            validate_destination(BitcoinNetwork::Testnet3, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap_err();
        assert!(matches!(err, DomainError::BitcoinNetworkMismatch(_)));
    }

    #[test]
    fn testnet3_accepts_opaque_lab_tag() {
        assert!(validate_destination(BitcoinNetwork::Testnet3, "tb1q-users-withdraw").is_ok());
        assert!(validate_destination(BitcoinNetwork::Testnet3, "ln-users-withdraw").is_ok());
    }

    #[test]
    fn testnet3_accepts_tb1() {
        // Well-known testnet P2WPKH from bitcoin examples / BIP173.
        let addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        assert!(validate_destination(BitcoinNetwork::Testnet3, addr).is_ok());
    }
}
