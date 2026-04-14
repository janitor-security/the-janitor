# FIPS 140-3 Cryptographic Boundary Definition

## Scope

This document defines the cryptographic boundary for The Janitor v10.1.4 in the format expected by FIPS 140-3 assessors. The boundary statement is aligned to the CMVP security-policy guidance in NIST SP 800-140B Rev. 1 and enumerates each security-relevant cryptographic operation performed by the product.

The boundary for this release is the set of cryptographic operations whose outputs are used to make a security decision, establish integrity, or prove provenance. Performance-only hashing and non-security deduplication are outside this boundary.

## Boundary Statement

The Janitor's in-scope cryptographic boundary includes:

- Governor transparency log chaining used to prove append-only audit integrity.
- Policy manifest hashing used to detect governance drift.
- Detached CBOM and release-signature generation used to establish provenance.

The following table is the authoritative cryptographic operation inventory for this release.

| Operation | Algorithm | Crate | NIST Standard | CMVP Status |
|-----------|-----------|-------|---------------|-------------|
| Governor Log Chain | SHA-384 | `sha2` | FIPS 180-4 | Pending POA&M |
| Policy Hash | SHA-256 | `sha2` | FIPS 180-4 | Pending POA&M |
| CBOM/Release Signatures | ML-DSA-65 | `fips204` | FIPS 204 | Pending POA&M |
| CBOM/Release Signatures | SLH-DSA-SHAKE-192s | `fips205` | FIPS 205 | Pending POA&M |

## CMVP Posture

The implementation uses NIST-standardized algorithms, but this repository does not claim that the Rust crates listed above are CMVP-validated cryptographic modules. The current posture is therefore Pending POA&M until those algorithm implementations are wrapped in, or replaced by, a CMVP-validated module boundary acceptable to the assessor.

Post-quantum digital signatures were standardized by NIST on August 13, 2024, when FIPS 204 and FIPS 205 were published. CMVP validation lag for new PQC implementations is therefore expected industry-wide at this stage of the lifecycle. The current pending posture for `fips204` and `fips205` is normal for August 2024-generation PQC adoption and must be tracked as a formal Plan of Action and Milestones item until CMVP-validated modules are available.
