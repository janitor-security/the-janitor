# Hunt Report — transferwise/tw-tasks-executor

**Sprint**: Batch 99
**Date**: 2026-05-03
**Engagement**: wise_targets
**Repo**: https://github.com/transferwise/tw-tasks-executor (--depth 1)
**Hunter**: janitor hunt /tmp/transferwise-tasks --format bugcrowd

## Result: no_findings

Java Spring Boot distributed task execution framework.  No credential
leaks, no unsafe deserialization, no direct SQL injection sinks reachable
from network inputs without ORM parameterization.  `janitor hunt` exit 0,
zero structured findings.
