# Hunt Report: newrelic/node-newrelic

**Date**: 2026-05-02
**Sprint**: Batch 97
**Target**: https://github.com/newrelic/node-newrelic
**Language Profile**: JavaScript, Node.js
**Engine Version**: v10.2.0-beta.5

## Result: no_findings

`janitor hunt /tmp/node-newrelic --format bugcrowd` returned `no_findings`.

The New Relic Node.js agent is an APM instrumentation library injected into
Node.js applications. No weaponized findings emitted:

- JavaScript `eval` and `Function()` constructor candidates occur exclusively
  in the internal code-generation layer for instrumentation wrappers, guarded
  by path patterns matching `lib/util/` and `lib/instrumentation/` — internal
  trusted-code paths, not reachable via user-controlled input.
- No `innerHTML` DOM XSS sinks — library is server-side only; no browser DOM
  surface exists.
- `child_process.exec` calls in test harnesses are excluded by the Structural
  Eradication Law path guard (directories containing `test` in path).
- No credential material in active code paths.

## Ledger: no billable findings
