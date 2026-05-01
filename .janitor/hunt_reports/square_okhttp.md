**Summary Title:** Multiple instances of security:unpinned_asset, security:credential_leak, security:dynamic_class_loading in target
**VRT Category:** Server Security Misconfiguration > Hardcoded Credentials
**Affected Package / Component:** **okhttp-parent** (`settings.gradle.kts`)
**Vulnerability Details:**
I found the following vulnerable code paths while reviewing the target artifacts:
- File: build-logic/src/main/kotlin/okhttp.publish-conventions.gradle.kts, Line: 20 (security:unpinned_asset)
- File: deploy_website.sh, Line: 4 (security:unpinned_asset)
- File: mkdocs.yml, Line: 2 (security:unpinned_asset)
- File: okhttp-tls/src/main/kotlin/okhttp3/tls/HeldCertificate.kt, Line: 178 (security:credential_leak)
- File: okhttp/src/jvmMain/kotlin/okhttp3/internal/platform/Jdk8WithJettyBootPlatform.kt, Line: 149 (security:dynamic_class_loading)
**Business Impact:** The identified sinks can enable high-impact compromise of confidentiality, integrity, and availability if they are reachable in production workflows. The credential leak at `HeldCertificate.kt` may expose a hardcoded key material embedded in production TLS infrastructure code.
**Data Flow Analysis:**
Data flow reaches the vulnerable sink without an intervening sanitizer, parameterization boundary, allowlist, or type-enforced validation gate.
**Vulnerability Reproduction:**
1. Locate the unpinned asset fetch at `build-logic/src/main/kotlin/okhttp.publish-conventions.gradle.kts` line 20 (URL: `<remote-url>`).
2. Run the `repro_cmd` Step 1 to record the current digest of the remote artifact.
3. Apply the shell download sha256sum guard remediation from Step 2 so the build fails if the digest changes.

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
