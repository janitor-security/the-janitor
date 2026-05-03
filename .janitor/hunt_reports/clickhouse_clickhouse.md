# Hunt Report — ClickHouse/ClickHouse

**Sprint**: Batch 98  
**Date**: 2026-05-03  
**Engagement**: clickhouse_targets  
**Repo**: https://github.com/ClickHouse/ClickHouse (--depth 1)  
**Hunter**: janitor hunt /tmp/clickhouse-hunt --format bugcrowd  

## Result: no_findings

Findings emitted by the scanner were reviewed against the Threat Model Awareness
Law and Structural Eradication Law:

- `security:raw_pointer_deref` in `rust/workspace/prql/src/lib.rs` — unsafe FFI
  block in the embedded PRQL Rust library (a third-party sub-dependency). The
  unsafe block is an FFI boundary shim, not reachable from ClickHouse's SQL
  query ingestion path. Actor privilege required: compile-time contributor access.
  Approval% <10% — deleted.

- `security:command_injection` candidates in `base/base/coverage.cpp` — these
  are in the build-time coverage instrumentation layer, not the query execution
  engine. Actor privilege required: CI/build-system access. Not remotely
  exploitable via ClickHouse SQL. Approval% <5% — deleted.

No weaponized findings (concrete repro_cmd or HTML harness) produced.
