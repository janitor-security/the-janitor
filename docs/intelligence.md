# Intelligence Reports

Published forensic audits by The Janitor — structural PR analysis across open-source repositories.

Each audit package includes: PDF intelligence report, 16-column CSV audit trail, CycloneDX CBOM, and Swarm clone-pair data.

| Repository | Audit Date | Package |
|---|---|---|
| godotengine/godot | 2026-03-17 | [godot-audit-2026](https://github.com/janitor-security/godot-audit-2026) |
| kubernetes/kubernetes | 2026-03-25 | [kubernetes-audit-2026](https://github.com/janitor-security/kubernetes-audit-2026) |

---

## Audited Repositories

### Godot Engine

**Repository**: [github.com/godotengine/godot](https://github.com/godotengine/godot)

Polyglot C++ game engine. 3.5 million lines across C++, C#, Java, Objective-C, GLSL, and Python.

Findings: 717 dead symbols (library mode), 8 antipatterns (raw `new` usage in C++ PRs), 69/98 PRs unlinked to issues. Peak RSS: 58 MB. Zero OOM events.

### Kubernetes

**Repository**: [github.com/kubernetes/kubernetes](https://github.com/kubernetes/kubernetes)

Go container orchestration platform. 166 MB peak RSS. 4 antipatterns (open CIDR ingress rules in HCL), 85/98 PRs unlinked.
