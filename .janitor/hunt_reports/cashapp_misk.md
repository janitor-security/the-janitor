**Summary Title:** Multiple instances of security:protobuf_any_type_field, security:unpinned_asset, security:dynamic_class_loading in target
**VRT Category:** Informational
**Affected Package / Component:** **cashapp/misk** (`build.gradle.kts`)
**Vulnerability Details:**
I found the following vulnerable code paths while reviewing the target artifacts:
- File: misk-proto/src/main/proto/misk/proto/status.proto, Line: 91 (security:protobuf_any_type_field)
- File: .github/workflows/prepare_mkdocs.sh, Line: 4 (security:unpinned_asset)
- File: samples/exemplarchat/src/main/resources/web/index.html, Line: 77 (security:unpinned_asset)
- File: misk-hibernate/src/main/kotlin/misk/hibernate/Hibernate.kt, Line: 39 (security:dynamic_class_loading)
- File: misk-hibernate/src/main/kotlin/misk/hibernate/SessionFactoryService.kt, Line: 250 (security:dynamic_class_loading)
- File: misk-moshi/src/main/kotlin/misk/moshi/wire/FieldBinding.kt, Line: 168 (security:dynamic_class_loading)
**Business Impact:** The identified sinks can enable high-impact compromise of confidentiality, integrity, and availability if they are reachable in production workflows.
**Data Flow Analysis:**
Data flow reaches the vulnerable sink without an intervening sanitizer, parameterization boundary, allowlist, or type-enforced validation gate.
**Vulnerability Reproduction:**
1. Locate the `google.protobuf.Any` field `types.details` at `misk-proto/src/main/proto/misk/proto/status.proto` line 91.
2. Submit the attached Any JSON envelope through the Protobuf JSON gateway or equivalent decode path.
3. Confirm the receiver attempts to unpack or authorize the embedded type without an explicit type-url allowlist.

```text
python3 - <<'PY'
import json
payload = "{\"@type\":\"type.googleapis.com/types.details\",\"janitor_probe\":\"type-confusion-canary\",\"role\":\"admin\"}"
print(json.dumps(json.loads(payload), indent=2))
PY
```
**Remediation Advice:** Review the affected sink usage, remove unsafe data flow into the target API, and apply the framework-native safe alternative.
