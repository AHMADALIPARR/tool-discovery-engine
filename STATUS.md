# STATUS

## Verified in this workspace

- Ingest of the two 2026-11-07 source CSVs (881 inventory rows,
  178 signature rows) merges to 922 records; a second ingest seals
  to the identical head — the ingest is deterministic.
- `discover verify` recomputes the SHA-256 chain in C and reports
  VALID; a one-byte append to a copied registry is REFUSED.
- Search, describe (by index, name, and provider+name including
  the "MCP " prefix variant), and match return the expected
  records (browser_navigate, the T1 create_directory record,
  read_text_file for a file-reading task).
- All 91 provider manifests in integrations/mcp/ parse as JSON
  and carry 922 tools; the T1 create_directory manifest carries
  the converted JSON Schema with required ["path"].
- Test suite: 9/9 by execution (test/run-tests.sh).

## Limits

- Matching is keyword scoring over name, category, and provider —
  deterministic and inspectable, not semantic. Notes text is in
  the records for a future ranking pass.
- T4 records are names without captured schemas, and T5 records
  are representative operations: the manifests mark both honestly
  (x-schema-captured: false). Capturing the missing schemas is
  source work, not engine work.
- The registry is a snapshot of its two sources (2026-11-07);
  re-ingesting newer exports reseals it.
