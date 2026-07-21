# SEV-SNP test vectors

`azure_hcl_report_redacted.bin` / `azure_snp_report_redacted.bin` are a genuine
AMD SEV-SNP attestation report captured from an Azure confidential VM
(family 0x19 / model 0x01, "Milan"), read from the vTPM NV index `0x01400001`.

The 64-byte `CHIP_ID` field (offset 0x1a0 in the SNP report) has been **zeroed**:
it is a per-CPU hardware identifier. Zeroing it invalidates the report's ECDSA
signature, so these vectors exercise parsing, field offsets, and the Azure
`REPORT_DATA == sha256(runtime_data)` binding only. Signature and VCEK-chain
verification are covered by synthetic, self-consistent crypto generated in
`test_snp_verify.py` / `test_attestation_chain.py`.

The full real chain (unredacted report + real VCEK + AMD cert chain) was
validated on live Azure SEV-SNP silicon during development; that reproduction is
kept out of the repository because it embeds the hardware identifier.
