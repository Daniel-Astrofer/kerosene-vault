# Agent rules

- Treat this repository as a separate cryptographic trust domain.
- Never commit shares, nonces, ceremony output, private certificates, macaroons
  or TPM/TEE private material.
- Production must reject lab/dealer features at compile time.
- CI may publish release candidates but must never activate a signer.
- Protocol changes must consume versioned `kerosene-contracts` artifacts.
- Security-sensitive changes require focused tests and an updated threat model.
