# Command: /strike

Launch a full 1000-PR adversarial audit against a target repository.

## Usage

```
/strike <owner/repo>
```

## Mapped command

```bash
just strike <owner/repo> 1000
```

## Description

Runs the parallel bounce engine against the 1000 most recent PRs of the target
repository. Results are written to `.janitor/bounce_log.ndjson`.

Use `janitor report --format json` after completion to view the aggregate
threat summary.
