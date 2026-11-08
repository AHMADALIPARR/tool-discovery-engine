# Tool Discovery Engine

A sealed registry of the tools available to agents, and the engine
that discovers them. The registry models every tool two
evidence-graded source inventories record — 922 (provider, tool)
records across 93 providers at first ingest — and grades each
record by the evidence behind it. The engine answers discovery
queries over that model, so an agent carries five verbs instead of
nine hundred tool definitions: context is what the agent does not
need to carry.

## The model

Each record carries its provider, name, category, availability,
source, and an evidence tier:

- **T1** — parameter schema captured (14 records)
- **T2** — verified in a published source / exact registration (36)
- **T3** — documented tool (6)
- **T4** — published name only; schema not independently captured (128)
- **T5** — representative operation or shell-command exemplar (738)

A record is never promoted past its evidence. The registry is
sealed with a SHA-256 hash chain whose genesis is the two source
files' hashes; `discover verify` recomputes the chain and refuses
a tampered registry.

## The engine

`discover` (C11, zero dependencies) reads the registry:

- `discover coverage` — record, tier, and provider counts, and the
  context math: the byte cost of preloading every record versus
  the discovery surface.
- `discover search <term...>` — find tools by provider, name, or
  category.
- `discover describe <index | name | provider name>` — one full
  record, pulled only when needed.
- `discover match "<task>"` — the candidate tools for a task,
  ranked by relevance and evidence tier. Load only these.
- `discover verify` — recompute the seal.

## Integrations

`integrations/mcp/` holds one MCP manifest per provider — all 922
tools in `tools/list` shape. Tools with a captured schema (T1)
carry a real JSON Schema converted from the source parameter map;
the rest carry an empty schema marked `x-schema-captured: false`
with their evidence tier attached. The manifest states what is
known, not what would be convenient.

## Build and ingest

```sh
gcc -std=c11 -O2 -o discover src/discover.c
julia ingest/ingest.jl <inventory.csv> <signatures.csv> registry
./test/run-tests.sh
```

The ingest (Julia, stdlib only) is deterministic: the same sources
seal to the same head.
