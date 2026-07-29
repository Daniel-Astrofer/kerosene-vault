# Repository boundary

This repository is the canonical source for the Vault trust domain, including
FROST, DKG, reshare, signing policies, nonces and custody operations.

The root Cargo package is intentional while Vault remains one release unit.
Future daemons will be introduced as workspace members under `crates/` only
when they can be compiled and audited independently.

Vault consumes versioned protocols from `kerosene-contracts`. It must not read
source files from the archived monorepo or another service repository.
