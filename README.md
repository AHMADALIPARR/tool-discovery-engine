# Tool Discovery Engine

[![License: SnapKitty Opaque](https://img.shields.io/badge/license-SnapKitty%20Opaque-blue)](LICENSE)
[![C11](https://img.shields.io/badge/C-11-00599C?logo=c)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Julia](https://img.shields.io/badge/Julia-stdlib%20only-9558B2?logo=julia)](https://julialang.org)
[![Records](https://img.shields.io/badge/records-922-brightgreen)](STATUS.md)
[![Providers](https://img.shields.io/badge/providers-93-blue)](STATUS.md)
[![Seal](https://img.shields.io/badge/seal-VALID-success)](STATUS.md)
[![Tests](https://img.shields.io/badge/tests-9%2F9-brightgreen)](test/run-tests.sh)

A sealed, evidence-graded registry of the tools available to agents, and the zero-dependency C11 engine that discovers them.

The registry models every tool two evidence-graded source inventories record — 922 (provider, tool) records across 93 providers at first ingest — and grades each record by the evidence behind it. The engine answers discovery queries over that model, so an agent carries five verbs instead of nine hundred tool definitions. Context is what the agent does not need to carry.

## Topics

`tool-discovery` `mcp` `agents` `registry` `c11` `julia` `sealed-registry` `evidence-graded` `context-efficiency` `hash-chain` `zero-dependency`

## Evidence tiers

Each record carries its provider, name, category, availability, source, and an evidence tier. A record is never promoted past its evidence.

| Tier | Meaning | Count |
|------|---------|------:|
| **T1** | Parameter schema captured | 14 |
| **T2** | Verified in a published source / exact registration | 36 |
| **T3** | Documented tool | 6 |
| **T4** | Published name only; schema not independently captured | 128 |
| **T5** | Representative operation or shell-command exemplar | 738 |

The registry is sealed with a SHA-256 hash chain whose genesis is the two source files' hashes. `discover verify` recomputes the chain and refuses a tampered registry.

## The engine

`discover` (C11, zero dependencies) reads the registry:

| Command | Description |
|---------|-------------|
| `discover coverage` | Record, tier, and provider counts, plus the context math: byte cost of preloading every record versus the discovery surface. |
| `discover search <term...>` | Find tools by provider, name, or category. |
| `discover describe <index \| name \| provider name>` | One full record, pulled only when needed. |
| `discover match "<task>"` | Candidate tools for a task, ranked by relevance and evidence tier. Load only these. |
| `discover verify` | Recompute the seal. |

## Integrations

`integrations/mcp/` holds one MCP manifest per provider — all 922 tools in `tools/list` shape. Tools with a captured schema (T1) carry a real JSON Schema converted from the source parameter map; the rest carry an empty schema marked `x-schema-captured: false` with their evidence tier attached. The manifest states what is known, not what would be convenient.

## Build and ingest

```sh
gcc -std=c11 -O2 -o discover src/discover.c
julia ingest/ingest.jl <inventory.csv> <signatures.csv> registry
./test/run-tests.sh
```

The ingest (Julia, stdlib only) is deterministic: the same sources seal to the same head. Verified: second ingest seals to the identical head; `discover verify` reports VALID; a one-byte append is REFUSED. Test suite: 9/9.

## Status

See [STATUS.md](STATUS.md) for the verified workspace claims and known limits (keyword matching, snapshot date 2026-11-07, missing schemas marked honestly).

## License

[SnapKitty Opaque Source License](LICENSE) — research, study, internal evaluation, security analysis, and formal verification permitted. Commercial exploitation requires separate written authorization from the Licensor.

---

**SnapKitty Research Lab** · Bel esprit D'accord Trust
