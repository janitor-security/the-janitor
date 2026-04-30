**Summary Title:** Multiple instances of security:unpinned_asset in target
**VRT Category:** Informational
**Affected Package / Component:** **Afterpay** v1.0.0 (`*.podspec`)
**Vulnerability Details:**
I found the following vulnerable code paths while reviewing the target artifacts:
- File: Sources/Afterpay/Model/Environment.swift, Line: 23
**Business Impact:** The identified sinks can enable high-impact compromise of confidentiality, integrity, and availability if they are reachable in production workflows.
**Data Flow Analysis:**
Data flow reaches the vulnerable sink without an intervening sanitizer, parameterization boundary, allowlist, or type-enforced validation gate.
**Vulnerability Reproduction:**
1. Locate the unpinned asset fetch at `Sources/Afterpay/Model/Environment.swift` line 23 (URL: `<remote-url>`).
2. Run the `repro_cmd` Step 1 to record the current digest of the remote artifact.
3. Apply the shell download sha256sum guard remediation from Step 2 so the build fails if the digest changes.
4. Re-fetch the asset and verify the digest check passes (green) or detects drift (red).

```text
# Unpinned shell download — supply-chain substitution possible:
# Step 1: record the current digest:
curl -fsSL "<remote-url>" -o /tmp/janitor_asset_probe && sha256sum /tmp/janitor_asset_probe
# Step 2: apply an inline checksum guard:
# BEFORE (vulnerable):
#   curl -fsSL "<remote-url>" | bash
# AFTER  (safe):
#   EXPECTED_SHA256="<PASTE_HASH_FROM_STEP_1>"
#   curl -fsSL "<remote-url>" -o /tmp/install_script
#   echo "${EXPECTED_SHA256}  /tmp/install_script" | sha256sum --check
#   bash /tmp/install_script
# Drift proof: re-fetch and compare — a changed hash signals tampering.
curl -fsSL "<remote-url>" | sha256sum
```
**Remediation Advice:** Review the affected sink usage, remove unsafe data flow into the target API, and apply the framework-native safe alternative.
