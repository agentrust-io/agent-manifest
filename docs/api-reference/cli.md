# CLI reference

The `manifest` command is installed with the `cli` extra.

```bash
pip install "agent-manifest[cli]"
```

## Commands

### manifest create

Create and sign a new agent manifest.

```
manifest create [OPTIONS]

Options:
  --agent-id TEXT          SPIFFE URI identifying this agent role  [required]
  --issuer TEXT            SPIFFE URI of the signing authority  [required]
  --model TEXT             Model identifier (e.g. gpt-4o-2024-08-06)
  --prompt-file PATH       Path to the system prompt file (hashed, not stored)
  --ttl-hours INTEGER      Manifest validity window in hours  [default: 8]
  --crypto-profile TEXT    standard | post-quantum | hybrid  [default: standard]
  --out PATH               Output path for the signed manifest JSON
  --help                   Show this message and exit.
```

### manifest sign

Sign an existing manifest JSON with a key loaded from a file or environment variable.

```
manifest sign [OPTIONS] MANIFEST_FILE

Options:
  --key-file PATH          Path to Ed25519 private key (base64url, no padding)
  --key-env TEXT           Environment variable holding the private key
  --out PATH               Output path (defaults to overwriting MANIFEST_FILE)
  --help                   Show this message and exit.
```

### manifest verify

Verify a manifest against its signature and optional runtime context.

```
manifest verify [OPTIONS] MANIFEST_FILE

Options:
  --revocation-url TEXT    CRL endpoint to check for revocation
  --enforce-hitl           Fail if no valid HITL approval is present
  --enforce-attestation    Fail if no attestation report is present
  --min-slsa-level INT     Minimum SLSA level required  [default: 0]
  --help                   Show this message and exit.
```

### manifest revoke

Append a signed revocation record to a local CRL file.

```
manifest revoke [OPTIONS] MANIFEST_ID

Options:
  --crl-file PATH          Path to the JSON-Lines CRL file  [required]
  --reason TEXT            Revocation reason  [required]
  --revoked-by TEXT        SPIFFE URI or email of the revoking authority  [required]
  --key-file PATH          Path to the signing key  [required]
  --help                   Show this message and exit.
```

### manifest keygen

Generate a new Ed25519 key pair and write the private key to a file.

```
manifest keygen [OPTIONS]

Options:
  --out PATH               Output path for the private key (base64url, no padding)
  --print-pub              Print the public key to stdout after generation
  --help                   Show this message and exit.
```

### manifest attest

Run the auto-provider and print the attestation report as JSON.

```
manifest attest [OPTIONS]

Options:
  --provider TEXT          tpm | sev-snp | tdx | opaque | auto  [default: auto]
  --manifest-file PATH     Manifest to extend into the attestation register
  --help                   Show this message and exit.
```

## Source

::: agent_manifest.cli
