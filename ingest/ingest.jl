#!/usr/bin/env julia
# ingest.jl — build the sealed tool registry from the two source CSVs.
#
#   julia ingest/ingest.jl <inventory.csv> <signatures.csv> <out_dir>
#
# The registry is the model of every agent tool the sources know:
# one record per (provider, tool), graded by the evidence behind it.
# Tiers, highest evidence first:
#   T1  parameter schema captured in the signatures file
#   T2  verified in a published source / exact source registration
#   T3  documented tool (docs, protocol, tool type)
#   T4  published name only — schema NOT independently captured
#   T5  representative operation / shell-command exemplar
# Nothing is promoted past its evidence: a T4 record stays T4.
#
# Outputs in <out_dir>:
#   tools.tsv          line-format index for the C11 discovery engine
#   tools.jsonl        one JSON record per line, same order as the TSV
#   records/<n>.json   the same record, pretty, for `discover describe`
#   SEAL.txt           SHA-256 hash chain over tools.jsonl, genesis =
#                      the two source files' hashes
# And MCP manifests in <out_dir>/../integrations/mcp/<provider>.json.

using SHA

# --- a small RFC 4180 CSV reader (stdlib only) -----------------------
function read_csv(path)
    text = read(path, String)
    rows = Vector{String}[]
    row = String[]
    field = IOBuffer()
    inq = false
    i = firstindex(text)
    n = ncodeunits(text)
    push_field! = () -> push!(row, String(take!(field)))
    push_row! = () -> (push_field!(); push!(rows, row); row = String[])
    while i <= n
        c = text[i]
        if inq
            if c == '"'
                j = nextind(text, i)
                if j <= n && text[j] == '"'
                    print(field, '"'); i = j
                else
                    inq = false
                end
            else
                print(field, c)
            end
        else
            if c == '"'
                inq = true
            elseif c == ','
                push_field!()
            elseif c == '\n'
                push_row!()
            elseif c == '\r'
                # swallow; \n handles the row end
            else
                print(field, c)
            end
        end
        i = nextind(text, i)
    end
    (length(row) > 0 || position(field) > 0) && push_row!()
    header = rows[1]
    return [Dict(zip(header, r)) for r in rows[2:end] if length(r) == length(header) && any(!isempty, r)]
end

# --- JSON writing (escaped, deterministic key order) -----------------
jsonesc(s) = replace(replace(replace(replace(String(s), "\\" => "\\\\"), "\"" => "\\\""), "\n" => "\\n"), "\r" => "\\r") |> x -> replace(x, "\t" => "\\t")
jstr(s) = "\"" * jsonesc(s) * "\""
jval(::Nothing) = "null"
jval(s::AbstractString) = jstr(s)
jval(b::Bool) = b ? "true" : "false"
jval(v::Vector) = "[" * join(jval.(v), ",") * "]"

provider_key(p) = lowercase(strip(startswith(strip(p), "MCP ") ? strip(p)[5:end] : strip(p)))
slug(s) = replace(lowercase(strip(s)), r"[^a-z0-9]+" => "-")

function main()
    inv_path, sig_path, out_dir = ARGS[1], ARGS[2], ARGS[3]
    mkpath(joinpath(out_dir, "records"))
    mkpath(joinpath(dirname(out_dir), "integrations", "mcp"))
    inv = read_csv(inv_path)
    sig = read_csv(sig_path)

    records = Dict{String,Dict{String,Any}}()
    order = String[]
    function getrec!(prov, name)
        key = provider_key(prov) * "\u0001" * name
        if !haskey(records, key)
            records[key] = Dict{String,Any}("provider" => prov, "name" => name, "category" => "",
                "availability" => "", "evidence" => String[], "parameters" => nothing,
                "required" => String[], "default_enabled" => "", "source_url" => "",
                "notes" => "", "in_inventory" => false, "in_signatures" => false, "status" => "")
            push!(order, key)
        end
        records[key]
    end

    for r in inv
        rec = getrec!(r["provider_or_framework"], r["tool_or_operation"])
        rec["in_inventory"] = true
        rec["category"] = r["category"]
        rec["availability"] = r["startup_availability"]
        push!(rec["evidence"], r["evidence_class"])
        isempty(rec["source_url"]) && (rec["source_url"] = r["source_url"])
        isempty(rec["notes"]) && (rec["notes"] = r["notes"])
    end
    for r in sig
        rec = getrec!(r["provider"], r["tool_name"])
        rec["in_signatures"] = true
        isempty(rec["category"]) && (rec["category"] = r["category"])
        push!(rec["evidence"], r["source_type"])
        rec["status"] = r["status"]
        p = strip(r["parameters_json"])
        !isempty(p) && (rec["parameters"] = p)
        req = strip(r["required_parameters"])
        !isempty(req) && (rec["required"] = [strip(x) for x in split(req, ",")])
        rec["default_enabled"] = r["default_enabled"]
        isempty(rec["source_url"]) && (rec["source_url"] = r["source_url"])
        isempty(rec["notes"]) && (rec["notes"] = r["notes"])
    end

    function tier(rec)
        rec["parameters"] !== nothing && return "T1"
        s = rec["status"]
        (startswith(s, "verified in published source") || "exact_source_registration" in rec["evidence"]) && return "T2"
        # A source that explicitly says the schema was NOT captured
        # caps the record at T4, however well documented the name is.
        occursin("not independently captured", s) && return "T4"
        any(e -> e in ("documented_tool", "documented_tool_type", "protocol_method"), rec["evidence"]) && return "T3"
        any(e -> e in ("documented_historical_tool",), rec["evidence"]) || rec["in_signatures"] && return "T4"
        return "T5"
    end

    # --- emit registry ------------------------------------------------
    tsv = IOBuffer(); jsonl = IOBuffer()
    counts = Dict{String,Int}()
    by_provider = Dict{String,Vector{Dict{String,Any}}}()
    for (idx, key) in enumerate(order)
        rec = records[key]
        t = tier(rec)
        rec["tier"] = t
        counts[t] = get(counts, t, 0) + 1
        push!(get!(by_provider, provider_key(rec["provider"]), Dict{String,Any}[]), rec)
        san(s) = replace(replace(String(s), "\t" => " "), "\n" => " ")
        println(tsv, join([san(rec["provider"]), san(rec["name"]), san(rec["category"]), t,
                           san(rec["availability"]), rec["parameters"] === nothing ? "0" : "1",
                           san(rec["source_url"])], "\t"))
        line = "{" * join([
            "\"provider\":$(jstr(rec["provider"]))", "\"name\":$(jstr(rec["name"]))",
            "\"category\":$(jstr(rec["category"]))", "\"tier\":$(jstr(t))",
            "\"availability\":$(jstr(rec["availability"]))",
            "\"evidence\":$(jval(rec["evidence"]))",
            "\"parameters\":$(rec["parameters"] === nothing ? "null" : rec["parameters"])",
            "\"required\":$(jval(rec["required"]))",
            "\"default_enabled\":$(jstr(rec["default_enabled"]))",
            "\"source_url\":$(jstr(rec["source_url"]))", "\"notes\":$(jstr(rec["notes"]))",
            "\"in_inventory\":$(jval(rec["in_inventory"]))", "\"in_signatures\":$(jval(rec["in_signatures"]))",
        ], ",") * "}"
        println(jsonl, line)
        open(joinpath(out_dir, "records", "$idx.json"), "w") do io
            println(io, line)  # compact record; describe prints it verbatim
        end
    end
    write(joinpath(out_dir, "tools.tsv"), String(take!(tsv)))
    jsonl_str = String(take!(jsonl))
    write(joinpath(out_dir, "tools.jsonl"), jsonl_str)

    # --- seal ----------------------------------------------------------
    g = bytes2hex(sha256(read(inv_path))) * "+" * bytes2hex(sha256(read(sig_path)))
    tip = g
    for line in split(rstrip(jsonl_str, '\n'), "\n")
        tip = bytes2hex(sha256(tip * "|" * line))
    end
    open(joinpath(out_dir, "SEAL.txt"), "w") do io
        println(io, "genesis: $g")
        println(io, "records: $(length(order))")
        println(io, "head: $tip")
    end

    # --- MCP manifests --------------------------------------------------
    # inputSchema from a captured parameter map:
    #   {"path":{"type":"string","required":true}} ->
    #   {"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}
    function mcp_schema(rec)
        rec["parameters"] === nothing && return "{\"type\":\"object\",\"properties\":{},\"x-schema-captured\":false}"
        inner = rec["parameters"][2:end-1]  # strip outer braces of the property map
        props = String[]; req = String[]
        # split top-level properties on commas at depth 1
        depth = 0; cur = IOBuffer(); parts = String[]
        for ch in inner
            ch == '{' && (depth += 1); ch == '}' && (depth -= 1)
            if ch == ',' && depth == 0
                push!(parts, String(take!(cur)))
            else
                print(cur, ch)
            end
        end
        (position(cur) > 0 || !isempty(inner)) && push!(parts, String(take!(cur)))
        for part in parts
            m = match(r"^\s*\"([^\"]+)\"\s*:\s*(\{.*\})\s*$", part)
            m === nothing && continue
            pname, pdef = m.captures[1], m.captures[2]
            isreq = occursin("\"required\":true", replace(pdef, " " => ""))
            pdef_clean = replace(pdef, r",?\s*\"required\"\s*:\s*(true|false)" => "")
            push!(props, "\"$(jsonesc(pname))\":$pdef_clean")
            isreq && push!(req, pname)
        end
        return "{\"type\":\"object\",\"properties\":{" * join(props, ",") * "},\"required\":[" * join(jstr.(req), ",") * "]}"
    end
    n_integrated = 0
    for (prov, recs) in sort(collect(by_provider), by = first)
        tools = String[]
        for rec in sort(recs, by = r -> r["name"])
            n_integrated += 1
            desc = rec["category"] * (isempty(rec["notes"]) ? "" : " — " * rec["notes"])
            push!(tools, "{\"name\":$(jstr(rec["name"])),\"description\":$(jstr(desc)),\"inputSchema\":$(mcp_schema(rec)),\"x-evidence-tier\":$(jstr(rec["tier"]))}")
        end
        display = argmax(length, unique(r["provider"] for r in recs))
        manifest = "{\"server\":$(jstr(display)),\"tools\":[" * join(tools, ",") * "]}"
        write(joinpath(dirname(out_dir), "integrations", "mcp", slug(prov) * ".json"), manifest)
    end

    println("ingest: $(length(order)) records | tiers: ", join(["$k=$(counts[k])" for k in sort(collect(keys(counts)))], " "))
    println("ingest: MCP manifests for $(length(by_provider)) providers, $n_integrated tools integrated")
    println("ingest: seal head $tip")
end

main()
