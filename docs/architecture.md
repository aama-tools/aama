# A'ama — Architecture and Engagement Schema

A'ama is a containerized analysis workbench for z/OS mainframe security
assessments. It exposes Model Context Protocol (MCP) servers that let an AI
coding agent (Claude Code, Cursor, or any MCP-aware client) drive both
*static* analysis of engagement artifacts (RACF database unloads, SMF
records, JCL, SDSF output, USS file listings) and *live* interaction with a
target LPAR (over SSH+tsocmd or FTP+JES) under explicit, tiered scope
enforcement.

This document defines the contracts between A'ama's components — the
engagement layout on disk, the finding object format, the normalized
SQLite schema, the audit log format, and the policy/tier configuration.
Every component (intake service, static-mcp server, live-mcp server,
report builder) reads and writes against these contracts and must remain
agnostic of the others' implementations.

A'ama is named after the 'a'ama crab (*Grapsus tenuicrustatus*), the
sideways-scuttling rock crab native to Hawaiian shorelines.

---

## 1. Engagement directory layout

An *engagement* is the unit of work. One engagement corresponds to one
client + scope + timeframe, and lives in a single directory tree. Everything
A'ama produces about that engagement stays inside the tree; nothing leaks
to a shared location, cloud, or other engagement.

```
engagements/<engagement-id>/
  config.yaml              # engagement metadata, target spec, policy
  artifacts/               # raw uploads (immutable after intake writes them)
    racfdb/                # IRRDBU00 unloads
    smf/                   # SMF record dumps
    sdsf/                  # SDSF output captures
    jcl/                   # JCL files
    uss/                   # USS find / ls output, permissions dumps
    rexx/                  # REXX scripts and their output
    misc/                  # anything that didn't classify
  normalized.sqlite        # canonical analysis database (see §4)
  findings/                # one JSON file per finding (see §3)
    <finding-id>.json
  audit.log                # append-only live-mcp call log (see §5)
  reports/                 # generated drafts (docx, md)
  .schema_version          # integer; bumped on breaking layout changes
```

`<engagement-id>` is a short slug chosen by the operator at engagement
creation time (`acme-q1-2026`, `bank-lpar-prod-recon`). It must match
`^[a-z0-9][a-z0-9_-]{0,63}$`. The engagement directory is the unit of
backup, archival, and deletion: removing the directory removes everything
A'ama knows about the engagement.

The `artifacts/` subdirectory is **immutable after intake writes it**. Any
component that wants to transform an artifact reads it, writes the
derivative to `normalized.sqlite` or elsewhere, and leaves the original
untouched. This guarantees that re-running analysis on the same engagement
is deterministic given the same artifacts.

---

## 2. `config.yaml` — engagement configuration

Every engagement has exactly one `config.yaml` at its root. It is the
single source of truth for engagement metadata, target connection
parameters, and policy/tier configuration. A'ama refuses to start the
live-mcp server for an engagement that lacks a valid `config.yaml`.

```yaml
schema_version: 1

engagement:
  id: acme-q1-2026
  client: "ACME Financial"          # free text, used in report headers
  scope_summary: |
    LPAR SAPPROD (sa11) and LPAR DEV (sa12). RACF assessment plus
    USS configuration review. No CICS scope.
  start_date: 2026-01-15
  end_date:   2026-02-28
  operator:   "salty@example.com"   # for audit log attribution

target:                              # live-mcp connection parameters
  lpars:
    - name:    SAPPROD
      host:    10.42.1.10
      ssh_port: 22
      ftp_port: 21
      ssh_user: EV99
      # secrets are NEVER stored in config.yaml; loaded from environment
      # or a secrets file referenced here by path
      ssh_credential_ref: env:SAPPROD_SSH_KEY
      ftp_credential_ref: env:SAPPROD_FTP_PASS
      nje_node: GALPROD               # optional, for cross-node findings
    - name:    DEV
      host:    10.42.2.10
      # ...

racf_metadata:                       # tells static-mcp how to parse IRRDBU00
  unload_format: standard            # standard | extended
  installation_data_present: true
  custom_classes: [SURROGAT, FACILITY, OPERCMDS, XFACILIT]

policy:
  default_tier: 2                    # 1=allowlist-strict, 2=read-mostly, 3=write-with-approval
  rate_limit:
    commands_per_minute: 30
    bytes_per_minute: 1_048_576
  scope:
    allowed_ips:    [10.42.1.10, 10.42.2.10]
    allowed_ports:  [22, 21, 4000]
    forbidden_userids: [IBMUSER, ROOT, *SPECIAL]  # never operate as these
  tool_tiers:                        # override default_tier per tool category
    racf_read:        1
    omvs_read:        1
    sdsf_read:        1
    racf_write:       3
    job_submit:       3
    dataset_write:    3
    tsocmd_arbitrary: 3              # arbitrary tsocmd calls always need approval
  audit:
    log_path: audit.log
    hash_chain: true                 # each entry includes hash of previous

report:
  template: standard-pentest         # see /skills/reports/ in private repo
  severity_scale: cvss-equivalent    # cvss-equivalent | low-med-high-crit
  client_logo_path: null
```

A few notes on the choices here:

- **Secrets are referenced, never embedded.** `ssh_credential_ref: env:VAR`
  means "look up `VAR` in the process environment at connect time."
  Engagement directories may be shared, archived, or version-controlled;
  credentials must not be.
- **`forbidden_userids` is a safety belt.** Even at tier 3, the live-mcp
  layer will refuse to operate as a listed userid. This is the place to
  pin "never accidentally submit a job as IBMUSER even if I told you to."
- **`tool_tiers` overrides `default_tier`.** Default tier 2 means most
  read calls are allowed silently; write calls escalate. Setting
  `racf_write: 3` explicitly is redundant at default tier 2 (any tier
  ≥ default is honored) but documents intent. Setting `racf_read: 1`
  means even at default tier 2, RACF reads are evaluated under the
  *stricter* tier 1 rules (must be on the allowlist).

---

## 3. Finding object format

Findings are the unit of reportable output. Every detector (static or
live) that observes a security-relevant condition emits one or more
findings into `findings/`, one JSON file per finding, filename
`<finding-id>.json`.

```json
{
  "schema_version": 1,
  "id": "f-2026-0142",
  "created_at": "2026-02-12T14:33:21Z",
  "source": {
    "type": "static",
    "detector": "surrogat_submit_escalation_chain",
    "detector_version": "0.3.1"
  },
  "title": "SURROGAT class allows job submission as RACF SPECIAL administrator",
  "severity": "critical",
  "cvss_equivalent": 9.1,
  "category": "privilege-escalation",
  "subcategory": "racf-misconfiguration",
  "summary": "The SURROGAT profile '*.SUBMIT' has UACC=ALTER, permitting any authenticated user to submit jobs under the identity of any other userid. Userid AS72 holds RACF SPECIAL and is active; the engagement test userid EV99 can therefore submit JCL executing as AS72 and gain SPECIAL.",
  "affected_entities": [
    {"type": "racf-profile", "class": "SURROGAT", "name": "*.SUBMIT"},
    {"type": "userid",       "id": "AS72", "attributes": ["SPECIAL", "ACTIVE"]},
    {"type": "userid",       "id": "EV99", "context": "engagement test userid"}
  ],
  "evidence": [
    {
      "kind": "racf-profile-dump",
      "ref": "normalized.sqlite#racf_resource_profiles?class=SURROGAT&profile=*.SUBMIT"
    },
    {
      "kind": "audit-log-entry",
      "ref": "audit.log#2026-02-12T14:31:08Z",
      "description": "Job submission as AS72 succeeded, RC=0"
    }
  ],
  "replication_steps": [
    "Connect as EV99 via SSH+tsocmd.",
    "Confirm SURROGAT *.SUBMIT UACC=ALTER: `tsocmd \"RLIST SURROGAT *.SUBMIT\"`",
    "Submit JCL with USER=AS72; observe RC=0 and SPECIAL inherited."
  ],
  "remediation": "Reduce UACC on SURROGAT '*.SUBMIT' to NONE. Define explicit SURROGAT profiles per authorized submit relationship (e.g., SCHEDID.SUBMIT permitted to specific scheduler userids only). Audit existing job submission patterns before tightening.",
  "references": [
    {"label": "IBM RACF Security Administrator's Guide — SURROGAT class", "url": "https://www.ibm.com/docs/..."}
  ],
  "tags": ["racf", "surrogat", "privilege-escalation", "uacc"]
}
```

Field rules:

- `id` is unique within an engagement. The detector is free to choose any
  scheme; the convention `f-<year>-<sequence>` is suggested.
- `severity` is one of `informational | low | medium | high | critical`.
  `cvss_equivalent` is optional and only meaningful if `report.severity_scale`
  is `cvss-equivalent`.
- `source.type` is `static` (detector ran against `normalized.sqlite`) or
  `live` (observation came from a live-mcp tool call).
- `affected_entities` uses a controlled `type` vocabulary: `racf-profile`,
  `userid`, `group`, `dataset`, `uss-path`, `jcl-job`, `address-space`,
  `network-endpoint`. Detector authors extend this list via PR.
- `evidence` entries are *references*, not embedded data. The
  `normalized.sqlite#<query>` and `audit.log#<timestamp>` forms let the
  report builder fetch the underlying data at report-generation time;
  they also make findings comparatively small and diffable.
- `replication_steps` is freeform but should be runnable by another
  operator reading the report.

Findings are append-only within an engagement. To revise a finding, write
a new one and reference the old one in its `superseded_by` field (added
in a future schema version). Detectors must not modify existing finding
files.

---

## 4. Normalized SQLite schema

A'ama parses heterogeneous artifacts into a single SQLite database,
`normalized.sqlite`, that detectors and the agent can query uniformly.
This schema *extends* the schema defined by [racf2sql] for RACF database
unloads; tables defined there are used as-is, and A'ama adds tables for
the artifact types racf2sql does not cover.

[racf2sql]: https://github.com/mainframed/racf2sql

### Tables inherited from racf2sql

(Names representative; consult the racf2sql project for canonical
definitions.)

- `racf_users` — IRRDBU00 type 0200 records
- `racf_groups` — type 0100
- `racf_connect_data` — type 0205 (user-group connections)
- `racf_resource_profiles` — type 04xx (general resource profiles)
- `racf_dataset_profiles` — type 04xx (dataset profiles)
- `racf_access_lists` — type 0404, 0504 (resource and dataset ACLs)

### A'ama additions

```sql
-- SMF record summaries. Full record blobs stay in artifacts/smf/; this
-- table indexes them so detectors can query by type/time/user efficiently.
CREATE TABLE smf_events (
  id            INTEGER PRIMARY KEY,
  artifact_ref  TEXT NOT NULL,        -- relative path under artifacts/smf/
  byte_offset   INTEGER NOT NULL,     -- offset of the record in the artifact
  record_type   INTEGER NOT NULL,     -- SMF type (14, 30, 80, ...)
  record_subtype INTEGER,             -- if applicable
  timestamp     TEXT NOT NULL,        -- ISO-8601, derived from SMF timestamp
  system_id     TEXT,                 -- SMFID
  userid        TEXT,                 -- if applicable to the record type
  jobname       TEXT,
  summary_json  TEXT                  -- parsed key fields per record type
);
CREATE INDEX idx_smf_events_type_time ON smf_events(record_type, timestamp);
CREATE INDEX idx_smf_events_user      ON smf_events(userid);

-- USS file inventory from `find / -ls`-style dumps or equivalent.
CREATE TABLE uss_files (
  path          TEXT PRIMARY KEY,
  mode          INTEGER NOT NULL,     -- numeric mode (e.g., 0o755)
  owner_uid     INTEGER,
  owner_user    TEXT,                 -- resolved if available
  group_gid     INTEGER,
  group_name    TEXT,
  size_bytes    INTEGER,
  mtime         TEXT,                 -- ISO-8601
  is_setuid     INTEGER NOT NULL,     -- 0/1, derived from mode
  is_setgid     INTEGER NOT NULL,
  is_sticky     INTEGER NOT NULL,
  is_world_writable INTEGER NOT NULL,
  symlink_target TEXT                 -- NULL if not a symlink
);
CREATE INDEX idx_uss_files_world_writable ON uss_files(is_world_writable)
  WHERE is_world_writable = 1;
CREATE INDEX idx_uss_files_setuid ON uss_files(is_setuid)
  WHERE is_setuid = 1;

-- JCL parsed into structured edges. One row per (job, referenced resource).
CREATE TABLE jcl_references (
  id            INTEGER PRIMARY KEY,
  artifact_ref  TEXT NOT NULL,        -- relative path under artifacts/jcl/
  jobname       TEXT NOT NULL,
  jobcard_user  TEXT,                 -- USER= on JOB card if specified
  step_name     TEXT,                 -- EXEC step name
  program       TEXT,                 -- PGM= or PROC=
  reference_kind TEXT NOT NULL,       -- 'dataset' | 'proc' | 'user' | 'class'
  reference_value TEXT NOT NULL,      -- the referenced thing
  disposition   TEXT                  -- for datasets: NEW/OLD/SHR/MOD
);
CREATE INDEX idx_jcl_refs_value ON jcl_references(reference_value);
CREATE INDEX idx_jcl_refs_user  ON jcl_references(jobcard_user);

-- SDSF job output index. Like SMF, blobs stay in artifacts/sdsf/.
CREATE TABLE sdsf_jobs (
  id            INTEGER PRIMARY KEY,
  artifact_ref  TEXT NOT NULL,
  jobname       TEXT NOT NULL,
  jobid         TEXT NOT NULL,
  owner         TEXT,
  return_code   TEXT,                 -- RC=0000, ABEND S0C1, JCL ERROR, etc.
  submit_time   TEXT,
  end_time      TEXT
);

-- Dataset listings (from LISTC, LISTDSI, ISPF 3.4 captures, etc.).
CREATE TABLE datasets (
  name          TEXT PRIMARY KEY,
  dsorg         TEXT,                 -- PO, PS, VS, etc.
  recfm         TEXT,
  lrecl         INTEGER,
  blksize       INTEGER,
  volume        TEXT,
  is_apf        INTEGER NOT NULL DEFAULT 0,  -- 1 if listed in APF list
  is_linklib    INTEGER NOT NULL DEFAULT 0,
  is_proclib    INTEGER NOT NULL DEFAULT 0,
  created       TEXT,
  last_referenced TEXT
);

-- Network observations (TN3270/SSH banner captures, port states).
CREATE TABLE network_endpoints (
  id            INTEGER PRIMARY KEY,
  host          TEXT NOT NULL,
  port          INTEGER NOT NULL,
  service       TEXT,                 -- 'tn3270', 'ssh', 'ftp', 'http', etc.
  banner        TEXT,
  observed_at   TEXT NOT NULL,
  observed_by   TEXT,                 -- detector or tool that captured it
  metadata_json TEXT                  -- e.g. SSH KEX algorithms, TLS ciphers
);

-- Index of all detectors that have run against this engagement, with
-- results. Lets the agent ask "what has been checked?"
CREATE TABLE detector_runs (
  id            INTEGER PRIMARY KEY,
  detector_name TEXT NOT NULL,
  detector_version TEXT NOT NULL,
  run_at        TEXT NOT NULL,
  duration_ms   INTEGER,
  findings_count INTEGER NOT NULL,
  status        TEXT NOT NULL,        -- 'ok' | 'error' | 'partial'
  error_message TEXT
);
```

A `schema_version` row lives in a `meta` table:

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO meta (key, value) VALUES ('schema_version', '1');
INSERT INTO meta (key, value) VALUES ('aama_version', '0.1.0');
```

Migrations are versioned scripts under `tools/migrations/`; running A'ama
against an older `normalized.sqlite` triggers in-place migration after
explicit confirmation.

---

## 5. Audit log format

Every live-mcp tool call — issued, allowed, denied, escalated, or failed —
appends one record to `audit.log`. The file is append-only, line-delimited
JSON (`.jsonl`), one record per line. Each record includes a hash of the
previous record's serialized form, forming a tamper-evident chain.

```json
{"schema_version":1,"seq":1,"ts":"2026-02-12T14:30:55.121Z","actor":"agent","operator":"salty@example.com","engagement":"acme-q1-2026","lpar":"SAPPROD","tool":"racf_listuser","args":{"userid":"AS72"},"tier":1,"policy_decision":"allow","execution_status":"ok","duration_ms":312,"response_summary":"USER=AS72 SPECIAL ACTIVE GROUP=SYS1","response_bytes":4096,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"a3f1c9..."}
{"schema_version":1,"seq":2,"ts":"2026-02-12T14:31:08.502Z","actor":"agent","operator":"salty@example.com","engagement":"acme-q1-2026","lpar":"SAPPROD","tool":"submit_jcl","args":{"jcl_ref":"artifacts/jcl/surrogat-test.jcl","jobcard_user":"AS72"},"tier":3,"policy_decision":"approved","approver":"salty@example.com","approval_ts":"2026-02-12T14:31:02.119Z","execution_status":"ok","duration_ms":1841,"response_summary":"JOB12345 submitted, RC=0","response_bytes":2048,"prev_hash":"a3f1c9...","hash":"b7d402..."}
```

Field meanings:

- `seq` is monotonic per engagement. Detecting a gap (or a non-monotonic
  jump) indicates tampering or corruption.
- `actor` is `agent` (the LLM made the call) or `operator` (the human ran
  a command manually through A'ama's CLI). Both go in the same log.
- `tier` is the effective tier at the moment the call was evaluated.
- `policy_decision` is one of `allow`, `deny`, `escalate-pending`,
  `approved`, `denied-by-operator`. Tier 3 calls that the human approves
  produce both an `escalate-pending` entry and an `approved` entry; the
  intervening time is the deliberation latency.
- `response_summary` is a short, redacted summary suitable for logging.
  `response_bytes` is the full response size. Full responses are *not*
  written to the audit log — they go to `artifacts/` if they need to be
  kept.
- `hash` is `sha256(canonical_json(record_without_hash_field))`.
  `prev_hash` is the previous record's `hash`. The first record's
  `prev_hash` is 64 zeros.

Verification tool: `aama audit verify <engagement-id>` walks the file and
re-derives every hash, flagging any divergence.

---

## 6. Policy / tier model

A'ama enforces a three-tier scope-control model. Every live-mcp tool call
is evaluated against the current tier before execution; static-mcp calls
are tier-independent.

| Tier | Default behavior | Use case |
|------|------------------|----------|
| 1    | Allowlist-strict: only commands explicitly enumerated in `policy.allowed_commands` execute; everything else denied. | Compliance audit, highly sensitive client. |
| 2    | Read-mostly: read-class commands execute silently; write-class commands escalate to human approval. (Default.) | Standard pentest. |
| 3    | Write-with-approval: any command may execute, but write-class commands trigger an MCP elicitation prompt to the human before running. | Authorized exploit/escalation testing. |

Tier is set per-engagement in `config.yaml` as `policy.default_tier`. It
can be overridden per-tool via `policy.tool_tiers`. A higher per-tool tier
than the engagement default is honored (stricter wins); a lower per-tool
tier than the default is also honored but logged as a permission
elevation.

Tool categories (used in `policy.tool_tiers`):

- `racf_read` — RLIST, LISTUSER, LISTGRP, SEARCH (read-only)
- `racf_write` — PERMIT, ALTUSER, RDEFINE, etc.
- `omvs_read` — `ls`, `find`, `cat`, file metadata
- `omvs_write` — `cp`, `mv`, `chmod`, redirection-based writes
- `omvs_exec` — running scripts or binaries
- `sdsf_read` — fetching job output, listing queues
- `sdsf_write` — cancelling jobs, purging output
- `dataset_read` — IEBGENER copy-to-stdout, ISPF browse equivalent
- `dataset_write` — allocation, member writes
- `job_submit` — JCL submission via FTP/JES or SUBMIT command
- `tsocmd_arbitrary` — fall-through for any TSO command not in another category

Escalation flow (tier 3 write or any tier-3-categorized tool):

1. Agent invokes the tool with arguments.
2. Policy middleware records `escalate-pending` in the audit log and
   issues an MCP `elicitation/create` to the client with a summary:
   "Agent wants to submit JCL as user AS72. Proceed? [yes/no/reason]"
3. Human responds via the client UI.
4. Approval (or denial) is recorded in the audit log with the approver's
   identity and a free-text rationale.
5. If approved, the tool executes and the result is recorded normally.
6. If denied, the tool returns an error to the agent indicating the
   denial reason.

Rate limits in `policy.rate_limit` are evaluated independently of tier.
A rate-limit denial is logged as `policy_decision: "deny"` with
`deny_reason: "rate-limit"`.

---

## 7. Extension points

### Detector plugin interface (static-mcp)

A detector is a Python class implementing:

```python
class Detector:
    name: str                # snake_case identifier
    version: str             # semver
    category: str            # 'racf-misconfiguration', 'uss-permissions', etc.
    description: str         # one-line summary
    default_severity: str    # 'informational' | 'low' | ... | 'critical'

    def applicable(self, db: sqlite3.Connection) -> bool:
        """Return True if this detector has the data it needs to run."""

    def evaluate(self, db: sqlite3.Connection,
                 engagement_dir: pathlib.Path) -> list[Finding]:
        """Run the detector. Return zero or more Finding objects."""
```

Detectors register themselves via Python entry points (`aama.detectors`),
so the public scaffolding can load both built-in and externally-installed
detectors without code changes.

### Live-mcp tool interface

Every live tool is registered with: its category (for tier mapping), an
argument schema (JSON Schema), and a callable that executes against an
established LPAR session. The tool registry exposes the categorized list
to the policy middleware at evaluation time.

### Report templates

Reports are generated by composing finding sections from a template
defined in the private repo. Templates accept a list of Finding objects
filtered/sorted/grouped as the template specifies, and emit Markdown
or DOCX. The public repo defines only the template *interface* (input
types, output formats); the templates themselves live alongside the
detectors that produce findings, in the private repo.

---

## 8. Schema versioning and forward compatibility

Every artifact format defined here carries a `schema_version` integer.
A'ama refuses to operate on engagements whose schema version is newer
than it understands, and offers in-place migration for older versions
via `aama migrate <engagement-id>`.

Compatibility promises:

- Within a major schema version, fields may be *added* but not removed
  or repurposed. Consumers must ignore unknown fields.
- Field removals or semantic changes require a major version bump and
  a migration script.
- The `findings/` directory's per-file format is independent of the
  rest; a finding written under schema v1 remains readable forever as
  long as its consumers respect the version field.

---

## 9. Out of scope (for this document)

The following concerns are real but live in other documents:

- **Container hardening and seccomp profiles** — see `docs/sandboxing.md`.
- **Network isolation between intake, static-mcp, live-mcp, and the
  outside world** — see `docs/networking.md`.
- **Report template authoring** — private repo, not public.
- **Specific detector implementations** — only the framework is public;
  most detectors are private.
- **MCP server transport details** — A'ama follows the standard MCP
  HTTP streaming transport; clients configure servers per the standard
  `mcp.json` schema.

---

## Appendix A — Example minimal engagement

A fresh engagement created with `aama init acme-q1-2026` produces:

```
engagements/acme-q1-2026/
  config.yaml              # template, requires editing
  artifacts/
    racfdb/
    smf/
    sdsf/
    jcl/
    uss/
    rexx/
    misc/
  normalized.sqlite        # empty, schema v1 initialized
  findings/                # empty
  audit.log                # empty
  reports/                 # empty
  .schema_version          # contains: 1
```

The operator edits `config.yaml`, uploads artifacts via the intake
service, and starts the MCP servers. From then on, the agent drives.
