# Kerosene Vault

Isolated Rust custody and signing appliance for Kerosene.

This repository owns threshold signing, FROST/DKG/reshare, nonce policy,
attestation adapters and Vault release validation. Its CI must never receive
production shares, TPM private material, LND macaroons or deployment authority.

The current code was extracted from `Daniel-Astrofer/Kerosene` with history
preserved. Formatting enforcement is temporarily disabled in CI until the
existing crate receives a dedicated baseline-format commit.
