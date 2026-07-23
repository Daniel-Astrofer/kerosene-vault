//! FROST share refresh (reshare) via frost-secp256k1 multi-round refresh DKG.
//!
//! Preserves the group verifying key while rotating participant shares.
//! In-process N-party simulation for lab/Gate; over-wire exchange is out of scope here.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use frost_secp256k1 as frost;
use frost_secp256k1::keys::refresh::{
    refresh_dkg_part1, refresh_dkg_part2, refresh_dkg_shares,
};
use frost_secp256k1::keys::{KeyPackage, PublicKeyPackage};
use frost_secp256k1::Identifier;
use rand::rngs::OsRng;

use crate::application::{LedgerPort, ReshareHookPort};
use crate::domain::{
    DayEpoch, DomainError, LedgerEntry, LedgerEventKind, NodeId, ResharePolicy,
};

/// Live FROST material shared between sign orchestrator and reshare hook.
#[derive(Clone)]
pub struct FrostShareState {
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    pub pubkey_package: PublicKeyPackage,
    pub min_signers: usize,
}

/// Slot holding optional FROST material (installed after DKG).
pub struct FrostShareSlot {
    inner: Mutex<Option<FrostShareState>>,
}

impl FrostShareSlot {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    pub fn install(&self, state: FrostShareState) {
        *self.inner.lock().expect("frost share slot") = Some(state);
    }

    pub fn snapshot(&self) -> Result<FrostShareState, DomainError> {
        self.inner
            .lock()
            .expect("frost share slot")
            .clone()
            .ok_or_else(|| DomainError::ThresholdError("FROST material not installed".into()))
    }

    pub fn replace(&self, state: FrostShareState) {
        *self.inner.lock().expect("frost share slot") = Some(state);
    }
}

impl Default for FrostShareSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Multi-round FROST refresh DKG across all installed participants (n-party sim).
pub fn refresh_shares_in_process(
    old_key_packages: &BTreeMap<Identifier, KeyPackage>,
    old_pubkey: &PublicKeyPackage,
) -> Result<(BTreeMap<Identifier, KeyPackage>, PublicKeyPackage), DomainError> {
    if old_key_packages.is_empty() {
        return Err(DomainError::ThresholdError(
            "reshare requires at least one key package".into(),
        ));
    }
    let identifiers: Vec<Identifier> = old_key_packages.keys().copied().collect();
    let max_signers = identifiers.len() as u16;
    let min_signers = *old_key_packages
        .values()
        .next()
        .map(|kp| kp.min_signers())
        .ok_or_else(|| DomainError::ThresholdError("empty key packages".into()))?;
    if max_signers < 2 || min_signers < 2 || min_signers > max_signers {
        return Err(DomainError::ThresholdError(format!(
            "bad reshare params: max={max_signers} min={min_signers}"
        )));
    }

    let mut rng = OsRng;

    // --- Round 1 ---
    let mut round1_secrets = BTreeMap::new();
    let mut round1_packages = BTreeMap::new();
    for id in &identifiers {
        let (secret, package) = refresh_dkg_part1(*id, max_signers, min_signers, &mut rng)
            .map_err(|e| DomainError::ThresholdError(format!("frost refresh part1: {e}")))?;
        round1_secrets.insert(*id, secret);
        round1_packages.insert(*id, package);
    }

    // --- Round 2 ---
    let mut round2_secrets = BTreeMap::new();
    let mut round2_inbox: BTreeMap<
        Identifier,
        BTreeMap<Identifier, frost::keys::dkg::round2::Package>,
    > = BTreeMap::new();
    for id in &identifiers {
        let mut received = round1_packages.clone();
        received.remove(id);
        let secret = round1_secrets
            .remove(id)
            .ok_or_else(|| DomainError::ThresholdError("missing refresh round1 secret".into()))?;
        let (r2_secret, outbound) = refresh_dkg_part2(secret, &received)
            .map_err(|e| DomainError::ThresholdError(format!("frost refresh part2: {e}")))?;
        round2_secrets.insert(*id, r2_secret);
        for (receiver, package) in outbound {
            round2_inbox
                .entry(receiver)
                .or_default()
                .insert(*id, package);
        }
    }

    // --- Round 3: refresh_dkg_shares; group verifying key must be unchanged ---
    let old_vk = *old_pubkey.verifying_key();
    let mut new_key_packages = BTreeMap::new();
    let mut new_pubkey: Option<PublicKeyPackage> = None;
    for id in &identifiers {
        let mut r1_received = round1_packages.clone();
        r1_received.remove(id);
        let r2_received = round2_inbox.get(id).ok_or_else(|| {
            DomainError::ThresholdError(format!("missing refresh round2 inbox for {id:?}"))
        })?;
        let r2_secret = round2_secrets.get(id).ok_or_else(|| {
            DomainError::ThresholdError("missing refresh round2 secret".into())
        })?;
        let old_kp = old_key_packages.get(id).ok_or_else(|| {
            DomainError::ThresholdError(format!("missing old key package for {id:?}"))
        })?;
        let (kp, pk) = refresh_dkg_shares(
            r2_secret,
            &r1_received,
            r2_received,
            old_pubkey.clone(),
            old_kp.clone(),
        )
        .map_err(|e| DomainError::ThresholdError(format!("frost refresh part3: {e}")))?;

        if *kp.min_signers() != min_signers {
            return Err(DomainError::ThresholdError(format!(
                "reshare threshold drift: got {} want {min_signers}",
                kp.min_signers()
            )));
        }
        if *pk.verifying_key() != old_vk {
            return Err(DomainError::ThresholdError(
                "reshare changed group verifying key (forbidden)".into(),
            ));
        }
        new_key_packages.insert(*id, kp);
        new_pubkey = Some(pk);
    }

    let pubkey = new_pubkey
        .ok_or_else(|| DomainError::ThresholdError("reshare produced no pubkey package".into()))?;
    Ok((new_key_packages, pubkey))
}

fn append_ledger_event(
    ledger: &dyn LedgerPort,
    writer: &NodeId,
    kind: LedgerEventKind,
    payload: &str,
) -> Result<(), DomainError> {
    let epoch = ledger.epoch()?.number;
    let prev = ledger
        .head()?
        .map(|e| e.entry_hash)
        .unwrap_or_else(|| "genesis-prev".into());
    let next_index = ledger.entries()?.len() as u64;
    let entry = LedgerEntry::chain(next_index, epoch, kind, payload, writer.clone(), &prev);
    ledger.append(entry)
}

/// Policy-driven reshare hook: constitution ledger events + optional FROST refresh.
pub struct PolicyReshareHook {
    policy: ResharePolicy,
    ledger: Arc<dyn LedgerPort>,
    writer: NodeId,
    shares: Arc<FrostShareSlot>,
}

impl PolicyReshareHook {
    pub fn new(
        policy: ResharePolicy,
        ledger: Arc<dyn LedgerPort>,
        writer: NodeId,
        shares: Arc<FrostShareSlot>,
    ) -> Self {
        Self {
            policy,
            ledger,
            writer,
            shares,
        }
    }

    fn record_day_advanced(&self, from: &DayEpoch, to: &DayEpoch) -> Result<(), DomainError> {
        let constitution = self.ledger.constitution()?;
        let payload = format!(
            r#"{{"from":"{}","to":"{}","constitution_hash":"{}","reshare_policy":"{}"}}"#,
            from.as_str(),
            to.as_str(),
            constitution.hash,
            self.policy.as_str()
        );
        append_ledger_event(
            self.ledger.as_ref(),
            &self.writer,
            LedgerEventKind::DayAdvanced,
            &payload,
        )
    }

    fn run_reshare(&self, reason: &str, from_day: Option<&DayEpoch>, to_day: Option<&DayEpoch>) -> Result<(), DomainError> {
        let snap = self.shares.snapshot()?;
        let old_vk_hex = hex::encode(
            snap.pubkey_package
                .verifying_key()
                .serialize()
                .map_err(|e| DomainError::ThresholdError(format!("vk serialize: {e}")))?,
        );
        let (new_packages, new_pubkey) =
            refresh_shares_in_process(&snap.key_packages, &snap.pubkey_package)?;
        let new_vk_hex = hex::encode(
            new_pubkey
                .verifying_key()
                .serialize()
                .map_err(|e| DomainError::ThresholdError(format!("vk serialize: {e}")))?,
        );
        if old_vk_hex != new_vk_hex {
            return Err(DomainError::ThresholdError(
                "reshare verifying key mismatch".into(),
            ));
        }
        let min_signers = snap.min_signers;
        self.shares.replace(FrostShareState {
            key_packages: new_packages,
            pubkey_package: new_pubkey,
            min_signers,
        });

        let constitution = self.ledger.constitution()?;
        let payload = format!(
            r#"{{"reason":"{}","participants":{},"min_signers":{},"verifying_key":"{}","constitution_hash":"{}","from_day":"{}","to_day":"{}"}}"#,
            reason,
            snap.key_packages.len(),
            min_signers,
            new_vk_hex,
            constitution.hash,
            from_day.map(|d| d.as_str()).unwrap_or(""),
            to_day.map(|d| d.as_str()).unwrap_or(""),
        );
        append_ledger_event(
            self.ledger.as_ref(),
            &self.writer,
            LedgerEventKind::ReshareCompleted,
            &payload,
        )
    }
}

impl ReshareHookPort for PolicyReshareHook {
    fn policy(&self) -> ResharePolicy {
        self.policy
    }

    fn on_day_advance(&self, from: &DayEpoch, to: &DayEpoch) -> Result<(), DomainError> {
        self.record_day_advanced(from, to)?;
        match self.policy {
            ResharePolicy::Daily => self.run_reshare("day_advance", Some(from), Some(to)),
            ResharePolicy::Manual => Ok(()),
        }
    }

    fn trigger_manual(&self, reason: &str) -> Result<(), DomainError> {
        self.run_reshare(reason, None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::DistributedDkgAdapter;
    use crate::adapters::InMemoryLedger;
    use crate::domain::Constitution;

    #[test]
    fn refresh_n3_preserves_group_key_and_can_sign() {
        let bundle = DistributedDkgAdapter::run_in_process(3, 2).unwrap();
        let old_vk = *bundle.pubkey_package.verifying_key();
        let (new_packages, new_pk) =
            refresh_shares_in_process(&bundle.key_packages, &bundle.pubkey_package).unwrap();
        assert_eq!(new_packages.len(), 3);
        assert_eq!(*new_pk.verifying_key(), old_vk);
        let mut changed = false;
        for (id, old_kp) in &bundle.key_packages {
            let new_kp = &new_packages[id];
            if old_kp.signing_share() != new_kp.signing_share() {
                changed = true;
                break;
            }
        }
        assert!(changed, "expected refreshed signing shares to differ");
    }

    #[test]
    fn policy_daily_writes_day_and_reshare_ledger_events() {
        let constitution = Constitution::v1_lab(3).unwrap();
        let writer = NodeId::new("vault-1").unwrap();
        let ledger = Arc::new(
            InMemoryLedger::genesis(
                constitution,
                vec![
                    writer.clone(),
                    NodeId::new("vault-2").unwrap(),
                    NodeId::new("vault-3").unwrap(),
                ],
                writer.clone(),
            )
            .unwrap(),
        );
        let shares = Arc::new(FrostShareSlot::new());
        let bundle = DistributedDkgAdapter::run_in_process(3, 2).unwrap();
        shares.install(FrostShareState {
            key_packages: bundle.key_packages,
            pubkey_package: bundle.pubkey_package,
            min_signers: 2,
        });
        let hook = PolicyReshareHook::new(
            ResharePolicy::Daily,
            ledger.clone(),
            writer,
            shares,
        );
        let from = DayEpoch::parse("2024-01-01").unwrap();
        let to = DayEpoch::parse("2024-01-02").unwrap();
        hook.on_day_advance(&from, &to).unwrap();

        let kinds: Vec<_> = ledger
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert!(kinds.contains(&LedgerEventKind::DayAdvanced));
        assert!(kinds.contains(&LedgerEventKind::ReshareCompleted));
    }

    #[test]
    fn policy_manual_skips_crypto_until_trigger() {
        let constitution = Constitution::v1_lab(3).unwrap();
        let writer = NodeId::new("vault-1").unwrap();
        let ledger = Arc::new(
            InMemoryLedger::genesis(
                constitution,
                vec![
                    writer.clone(),
                    NodeId::new("vault-2").unwrap(),
                    NodeId::new("vault-3").unwrap(),
                ],
                writer.clone(),
            )
            .unwrap(),
        );
        let shares = Arc::new(FrostShareSlot::new());
        let bundle = DistributedDkgAdapter::run_in_process(3, 2).unwrap();
        shares.install(FrostShareState {
            key_packages: bundle.key_packages,
            pubkey_package: bundle.pubkey_package,
            min_signers: 2,
        });
        let hook = PolicyReshareHook::new(
            ResharePolicy::Manual,
            ledger.clone(),
            writer,
            shares.clone(),
        );
        let from = DayEpoch::parse("2024-01-01").unwrap();
        let to = DayEpoch::parse("2024-01-02").unwrap();
        hook.on_day_advance(&from, &to).unwrap();
        let kinds: Vec<_> = ledger
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert!(kinds.contains(&LedgerEventKind::DayAdvanced));
        assert!(!kinds.contains(&LedgerEventKind::ReshareCompleted));

        hook.trigger_manual("ops").unwrap();
        let kinds: Vec<_> = ledger
            .entries()
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert!(kinds.contains(&LedgerEventKind::ReshareCompleted));
        assert!(shares.snapshot().is_ok());
    }
}
