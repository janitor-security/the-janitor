# Hunt Report: freedomofpress/securedrop-workstation

**Date**: 2026-05-02
**Sprint**: Batch 96
**Target**: https://github.com/freedomofpress/securedrop-workstation
**Language Profile**: Python, Salt/YAML, Makefile
**Engine Version**: v10.2.0-beta.5

## Result: no_findings

`janitor hunt /tmp/securedrop-workstation --format bugcrowd` returned `no_findings`.

The securedrop-workstation is a Qubes OS-based deployment harness. No weaponized findings emitted:

- Python scripts are provisioning/devops tooling; `subprocess` calls are intentional admin-level operations in a privileged VM context (dom0 QubesOS admin domain). Per Threat Model Awareness Law: admin-privilege-required operations are not remotely exploitable.
- Salt state YAML files define system configuration but do not expose user-controlled string injection paths.
- No JavaScript/TypeScript DOM surfaces — no innerHTML or fetch sinks.
- No credential material committed to repository.

## Ledger: no billable findings
