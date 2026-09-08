# Synthetic RSA signature-framing vector

This fixture isolates a byte-framing edge case. The 2048-bit PKCS#1 v1.5
SHA-256 signature is valid over `rsa-0014-attest.hex`, but its fixed-width
encoding happens to begin with `0x0014`, the TPM algorithm identifier for
RSASSA. It is nevertheless a documented legacy bare signature, not a
`TPMT_SIGNATURE` envelope.

The quote and original certificates were generated with the synthetic helpers in
`test_tpm_verify.py`. After the shared AK-chain verifier began enforcing CA
constraints, the same AK public key was re-certified under a fresh synthetic
root with `BasicConstraints(ca=True, path_length=0)` and certificate-signing
key usage. The quote, bare signature, AK public key, and validity windows are
unchanged; the root private key was used only in memory and was not saved. They are test cryptography only: they did not come from a
TPM, do not establish hardware provenance, and are not independent verification
evidence. The private key is intentionally not committed. The regression pins a
2026 verification time because the synthetic certificates expire in 2029.

The fixture was generated once with a fixed, freshly generated 2048-bit RSA AK.
The generator kept the PCR digest at `bytes(range(32, 64))` and enumerated
32-byte big-endian nonce counters from 0 through 7585, signing each quote with
PKCS#1 v1.5 and SHA-256. Counter 7585 produced the first signature whose prefix
matched any supported TPM signature scheme (`0x0014`, `0x0016`, or `0x0018`),
specifically `0x0014`. The committed test performs no search and needs only the
public fixture material to verify the signature.

SHA-256:

- `rsa-0014-attest.hex` decoded bytes:
  `532831280f45bb67304dcf4185ae8a7a18d104948168010f33cd69aac9daa23c`
- `rsa-0014-bare-signature.hex` decoded bytes:
  `7f6831c219923c0e60d855903c99b7ee702539cc0dc496a971269eb7763be24d`
- `rsa-0014-ak-chain.pem`:
  `bf71e89b0344aaf5133e04b3b7deb31951f578f978417dfc2c46d6b1b097c5ba`
- `rsa-0014-root.pem`:
  `08db314a6c106ff66d493056d81e81a3ec8a1eec1062a808ab602a2fd62a9a1d`
