# Release verification key contract

`release-signing-key.asc` is the broker's canonical public verification key.
This template intentionally contains no public-key body, fingerprint, identity
metadata, private key, or provisioning evidence. Runtime policy accepts only
the configured primary and role-specific subkey fingerprints.
