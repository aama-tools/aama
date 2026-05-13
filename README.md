# A'ama

Mainframe security analysis workbench.

A'ama exposes Model Context Protocol (MCP) servers that let an AI coding
agent drive z/OS security assessment work — both static analysis of
engagement artifacts (RACF database unloads, SMF records, JCL, SDSF
output, USS file listings) and live LPAR interaction (over SSH+tsocmd or
FTP+JES) — under explicit, tiered scope enforcement.

Named after the 'a'ama crab (*Grapsus tenuicrustatus*), the
sideways-scuttling rock crab native to Hawaiian shorelines.

> **Status: pre-alpha.** Architecture and engagement schema are defined;
> implementation has not begun. See [`docs/architecture.md`](docs/architecture.md).

## What it is, briefly

- **Intake service** — accepts engagement artifacts, classifies them by
  format, drops them into an engagement-scoped volume.
- **Static MCP server** — parses artifacts into a normalized SQLite
  database; detectors query that database and emit structured findings.
- **Live MCP server** — wraps SSH+tsocmd and FTP+JES access to a target
  LPAR with policy enforcement, tiered escalation, and a hash-chained
  audit log.
- **Report builder** — consumes findings and audit-log evidence to draft
  pentest reports.

## What's in this repo

The public scaffolding: schemas, the MCP server framework, the intake
service, the policy/tier enforcement layer, and a small set of example
detectors. The differentiated detector library, report templates, and
engagement playbooks live in a private companion repo.

## Documentation

- [Architecture and engagement schema](docs/architecture.md) — the
  contracts every component reads and writes against.

## Related work

A'ama is infrastructure-layer (RACF, USS, JCL, SDSF, datasets) and
deliberately does not duplicate existing tooling at adjacent layers:

- [hack3270](https://github.com/gglessner/hack3270) — TN3270 stream
  manipulation and CICS application-layer testing.
- [racf2sql](https://github.com/mainframed/racf2sql) — IRRDBU00 flat-file
  to SQLite translator. A'ama builds on its schema.
- [Enumeration](https://github.com/mainframed/Enumeration) — REXX-based
  on-LPAR enumeration script.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
