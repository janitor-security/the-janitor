# Hunt Report: transferwise/pipelinewise

**Date**: 2026-05-02
**Sprint**: Batch 96
**Target**: https://github.com/transferwise/pipelinewise
**Language Profile**: Python, YAML
**Engine Version**: v10.2.0-beta.5

## Result: no_findings

`janitor hunt /tmp/pipelinewise --format bugcrowd` returned `no_findings`.

The pipelinewise data pipeline tool is heavily Python with YAML pipeline config files. No weaponized findings were emitted:

- Python subprocess calls found are internal job execution entries guarded by config validation — taint flow does not reach from user-controlled input to unguarded `subprocess.run`.
- SQL sink calls operate through parameterized connector APIs (Singer tap/target protocol) with no direct string interpolation of user-controlled fields.
- No credential material in active paths (connection passwords are env-var injected).
- YAML config files contain connection templates but do not execute user-supplied shell strings without validation layers.

## Ledger: no billable findings
