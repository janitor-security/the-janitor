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
use forge::slop_hunter::find_slop;

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
    // Uses find_slop("rs", source) because the credential scan runs on ALL
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
        let findings = find_slop(entry.lang, entry.source);
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
];

/// Run the Blast Radius Bounce Gallery.
/// Returns `true` when all entries pass; `false` if any fail.
pub fn run_bounce_gallery() -> bool {
    use common::registry::SymbolRegistry;
    let registry = SymbolRegistry::default();
    let bouncer = PatchBouncer;

    let mut passed: usize = 0;
    let mut failed: usize = 0;

    for entry in BOUNCE_GALLERY {
        let patch = make_multi_dir_patch(entry.paths);
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

    /// Full gallery must pass — any detector regression here blocks `just audit`.
    #[test]
    fn threat_gallery_all_intercepted() {
        // Suppress stdout in test mode; only stderr failures are visible.
        assert!(
            run_gallery(),
            "Crucible: Threat Gallery breach — one or more detectors failed"
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
}
