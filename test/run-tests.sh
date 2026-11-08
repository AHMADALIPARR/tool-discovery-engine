#!/bin/sh
# Tool Discovery Engine — verification by execution.
set -e
cd "$(dirname "$0")/.."
JULIA=${JULIA:-$HOME/workspace/.tools/julia-1.11/bin/julia}
INV=${INV:-$HOME/workspace/user/files/agent_tool_inventory_2026-11-07.csv}
SIG=${SIG:-$HOME/workspace/user/files/verified_agent_mcp_tool_signatures_2026-11-07.csv}
pass=0; fail=0
ok() { if [ "$1" = 0 ]; then echo "  PASS  $2"; pass=$((pass+1)); else echo "  FAIL  $2"; fail=$((fail+1)); fi }

gcc -std=c11 -O2 -Wall -Wextra -o discover src/discover.c 2>/dev/null
ok $? "engine builds clean"

# ingest determinism: a second ingest seals to the same head
HEAD1=$(grep '^head:' registry/SEAL.txt | cut -d' ' -f2)
mkdir -p /tmp/tde-regen
"$JULIA" ingest/ingest.jl "$INV" "$SIG" /tmp/tde-regen/registry > /dev/null
HEAD2=$(grep '^head:' /tmp/tde-regen/registry/SEAL.txt | cut -d' ' -f2)
[ "$HEAD1" = "$HEAD2" ]; ok $? "ingest is deterministic (same seal head)"

./discover verify | grep -q "seal VALID"; ok $? "seal verifies"
./discover coverage | grep -q "records: 922"; ok $? "coverage counts 922 records"
./discover search playwright navigate | grep -q "browser_navigate"; ok $? "search finds browser_navigate"
./discover describe create_directory | grep -q '"tier":"T1"'; ok $? "describe returns the T1 record"
./discover match "read a text file from disk" | grep -q "read_text_file"; ok $? "match surfaces read_text_file"

# tamper refusal: flip one byte in a scratch registry
cp -r registry /tmp/tde-tampered
printf 'x' >> /tmp/tde-tampered/tools.jsonl
./discover --registry /tmp/tde-tampered verify | grep -q "REFUSED"; ok $? "tampered registry is refused"

# MCP manifests: every provider manifest parses; T1 schemas are real
python3 - << 'PY' > /dev/null
import json, glob
n = 0
for f in glob.glob('integrations/mcp/*.json'):
    m = json.load(open(f)); n += len(m['tools'])
    for t in m['tools']:
        assert 'inputSchema' in t and 'x-evidence-tier' in t
assert n == 922, n
m = json.load(open('integrations/mcp/filesystem.json'))
cd = [t for t in m['tools'] if t['name'] == 'create_directory'][0]
assert cd['inputSchema']['required'] == ['path'], cd
print('manifests ok')
PY
ok $? "922 tools integrated as MCP manifests; T1 schema converts"

echo "tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
