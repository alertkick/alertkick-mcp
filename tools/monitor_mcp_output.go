package tools

import (
	"bytes"
	"encoding/json"
)

// MCP server monitors ("mcp" type) store the watched server's tool list,
// tool descriptions, server instructions and lint excerpts on the monitor
// document (mcp_info, mcp_baseline). That text comes from a third-party MCP
// server and is untrusted: it is exactly the text a poisoned server uses to
// steer an agent. It must never be handed to the model calling these tools,
// so every tool that returns a monitor document passes it through
// sanitizeMonitorOutput first.
//
// What is removed (allowlist, so a field added later is dropped by default):
//   - mcp_info.instructions (server instructions excerpt)
//   - mcp_info.tools[] and mcp_baseline.tools[]: everything except name,
//     desc_bytes, read_only and destructive (so description and title go)
//   - mcp_info.findings[]: everything except key, rule, tool and accepted
//     (so the excerpt goes)
//   - mcp_headers: encrypted header secrets, present in raw list documents
//
// Each MCP monitor gains a compact mcp_summary instead. list_monitors
// (compact=true) drops mcp_info and mcp_baseline entirely and keeps only
// the summary.

var (
	mcpToolKeepKeys    = []string{"name", "desc_bytes", "read_only", "destructive"}
	mcpFindingKeepKeys = []string{"key", "rule", "tool", "accepted"}
)

// sanitizeMonitorOutput rewrites an API response holding one monitor, a list
// of monitors, or a paginated {"results": [...]} page. Responses without MCP
// fields are returned byte-for-byte unchanged.
func sanitizeMonitorOutput(data []byte, compact bool) []byte {
	var doc interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return data
	}
	changed := false
	visit := func(v interface{}) {
		if m, ok := v.(map[string]interface{}); ok && sanitizeMonitorDoc(m, compact) {
			changed = true
		}
	}
	switch v := doc.(type) {
	case map[string]interface{}:
		if results, ok := v["results"].([]interface{}); ok {
			for _, r := range results {
				visit(r)
			}
		} else {
			visit(v)
		}
	case []interface{}:
		for _, r := range v {
			visit(r)
		}
	}
	if !changed {
		return data
	}
	out, err := json.Marshal(doc)
	if err != nil {
		// Never fall back to the unsanitized body.
		return []byte(`{"error":"monitor response could not be prepared"}`)
	}
	return out
}

// sanitizeMonitorDoc strips untrusted MCP text from one monitor document in
// place and adds mcp_summary. It reports whether the document had MCP fields.
func sanitizeMonitorDoc(m map[string]interface{}, compact bool) bool {
	_, hasInfo := m["mcp_info"]
	_, hasBase := m["mcp_baseline"]
	_, hasHeaders := m["mcp_headers"]
	if !hasInfo && !hasBase && !hasHeaders && m["monitor_type"] != "mcp" {
		return false
	}
	delete(m, "mcp_headers")
	info, _ := m["mcp_info"].(map[string]interface{})
	base, _ := m["mcp_baseline"].(map[string]interface{})
	m["mcp_summary"] = mcpSummary(info, base)
	if compact {
		delete(m, "mcp_info")
		delete(m, "mcp_baseline")
		return true
	}
	if info != nil {
		delete(info, "instructions")
		keepKeysIn(info, "tools", mcpToolKeepKeys)
		keepKeysIn(info, "findings", mcpFindingKeepKeys)
	}
	if base != nil {
		keepKeysIn(base, "tools", mcpToolKeepKeys)
	}
	return true
}

// mcpSummary is the compact view of an MCP monitor's latest report: enough
// for an assistant to say what is wrong, with no tool text.
func mcpSummary(info, base map[string]interface{}) map[string]interface{} {
	s := map[string]interface{}{"has_baseline": base != nil}
	if info != nil {
		for _, k := range []string{"server_name", "server_version", "protocol_version", "tool_count", "tools_listed", "checked_at"} {
			if v, ok := info[k]; ok {
				s[k] = v
			}
		}
		drift, _ := info["drift"].([]interface{})
		s["drift_count"] = len(drift)
		open := 0
		findings, _ := info["findings"].([]interface{})
		for _, f := range findings {
			if fm, ok := f.(map[string]interface{}); ok && fm["accepted"] != true {
				open++
			}
		}
		s["findings_count"] = open
		if fails, ok := info["fails"].([]interface{}); ok && len(fails) > 0 {
			s["fails"] = fails
		}
		if len(drift) > 0 || open > 0 {
			s["review"] = "A person must review and accept these changes in the AlertKick web app. Accepting is not available over MCP or with an API key."
		}
	}
	if base != nil {
		tools, _ := base["tools"].([]interface{})
		s["baseline_tool_count"] = len(tools)
		for _, k := range []string{"accepted_at", "accepted_via"} {
			if v, ok := base[k]; ok {
				s["baseline_"+k] = v
			}
		}
	}
	return s
}

// keepKeysIn replaces parent[field], a JSON array of objects, with a copy
// that keeps only the listed keys. Non-object entries are dropped; any other
// non-null value is removed rather than passed through.
func keepKeysIn(parent map[string]interface{}, field string, keys []string) {
	v, present := parent[field]
	if !present || v == nil {
		return
	}
	arr, ok := v.([]interface{})
	if !ok {
		delete(parent, field)
		return
	}
	out := make([]interface{}, 0, len(arr))
	for _, e := range arr {
		em, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		kept := map[string]interface{}{}
		for _, k := range keys {
			if x, ok := em[k]; ok {
				kept[k] = x
			}
		}
		out = append(out, kept)
	}
	parent[field] = out
}
