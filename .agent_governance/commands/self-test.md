# Command: /self-test

Run the engine's sovereign integrity audit.

## Usage

```
/self-test
```

## Mapped command

```bash
janitor self-test
```

## Description

Executes the Ghost Attack simulation: injects a cryptominer string (Ghost Attack
A) and a version silo (Ghost Attack B) into synthetic fixtures and verifies the
engine flags them. Exits 0 with `SANCTUARY INTACT` on success; exits 1 with
`INTEGRITY BREACH` if any check fails.
