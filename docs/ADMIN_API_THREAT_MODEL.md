# Vault Admin API threat model

The initial Admin API is read-only and remains behind the existing authenticated
mTLS/token middleware. In hardened environments, only a Vault-role certificate
may call `/v1/admin/*`; a KFE certificate is rejected.

The responses expose readiness, roster counts, ceremony mode, protocol version
and public node identity. They never expose shares, nonces, passphrases, private
keys, seed material or certificate contents.

Production deployment should bind this surface to a local Unix socket or an
administrative network isolated from financial traffic. A future mutable
operation requires a separate requested/approved state machine, granular
authorization, idempotency and an integrity-protected audit event.

Set `VAULT_ADMIN_UNIX_SOCKET=/run/kerosene/vault-admin.sock` to create the
read-only local surface with mode `0660`. Startup refuses to replace a regular
file or symlink at that path. Ownership is inherited from the Vault process and
must be assigned to a dedicated operator group by the service manager. The
socket router contains only status and ceremony inspection routes; it cannot
reach signing, DKG, reshare, share or nonce handlers.
