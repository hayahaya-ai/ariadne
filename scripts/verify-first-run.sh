#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${ARIADNE_BIN:-"$repo_root/bin/ariadne"}"
fixture="${ARIADNE_VERIFY_FIXTURE:-"$repo_root/ariadne-prove/testdata/realpath/combined-risk"}"
endpoint_fixture="${ARIADNE_VERIFY_ENDPOINT_FIXTURE:-"$repo_root/ariadne-prove/testdata/realpath/messy-ai-surfaces"}"
workdir="$(mktemp -d "${TMPDIR:-/private/tmp}/ariadne-first-run.XXXXXX")"

expect_contains() {
  local file="$1"
  local needle="$2"
  if ! grep -Fq -- "$needle" "$file"; then
    echo "missing expected text in $file:" >&2
    echo "  $needle" >&2
    echo "artifacts left in: $workdir" >&2
    exit 1
  fi
}

echo "Ariadne first-run verification"
echo "  bin: $bin"
echo "  fixture: $fixture"
echo "  endpoint fixture: $endpoint_fixture"
echo "  artifacts: $workdir"

assess_txt="$workdir/assess.txt"
assess_json="$workdir/assess.json"
assess_html="$workdir/assess.html"
cases_txt="$workdir/cases.txt"
proofs_action="$workdir/proofs-action.txt"

"$bin" assess --path "$fixture" --out "$assess_txt"
"$bin" assess --path "$fixture" --format json --out "$assess_json"
"$bin" assess --path "$fixture" --format html --out "$assess_html"
"$bin" cases --path "$fixture" --out "$cases_txt"
"$bin" proofs --path "$fixture" --case case:input-trust-boundary --format action --out "$proofs_action"

expect_contains "$assess_txt" "What was inspected:"
expect_contains "$assess_txt" "Decision:"
expect_contains "$assess_txt" "Verdict: action required"
expect_contains "$assess_txt" "Inspected: AI surfaces:"
expect_contains "$assess_txt" "Inspected: Runtime surface map:"
expect_contains "$assess_txt" "Risk basis:"
expect_contains "$assess_txt" "Evidence fact:"
expect_contains "$assess_txt" "Claude Code settings declare broad local authority"
expect_contains "$assess_txt" "Before proof:"
expect_contains "$assess_txt" "--out before-proof.json"
expect_contains "$assess_txt" "Proof command:"
expect_contains "$assess_txt" "After proof:"
expect_contains "$assess_txt" "--out after-proof.json"
expect_contains "$assess_txt" "Decision limit:"
expect_contains "$assess_txt" "Decision is derived from deterministic inventory"
expect_contains "$assess_txt" "Signal triage:"
expect_contains "$assess_txt" "Normal capability:"
expect_contains "$assess_txt" "Missing hard barrier:"
expect_contains "$assess_txt" "Control state:"
expect_contains "$assess_txt" "Current control: control:egress-destination-allowlist"
expect_contains "$assess_txt" "Current proof surface: .ariadne/egress-policy.json"
expect_contains "$assess_txt" "Missing hard-barrier evidence for control:egress-destination-allowlist"
expect_contains "$assess_txt" "Path to fix:"
expect_contains "$assess_txt" "Supported graph edge:"
expect_contains "$assess_txt" "boundary external destination (reaches)"
expect_contains "$assess_txt" "First action:"
expect_contains "$assess_txt" "Save baseline proof before changes:"
expect_contains "$assess_txt" "Review/apply generated proof file:"
expect_contains "$assess_txt" "Generated proof file: proof-patches/surfaces/.ariadne/egress-policy.json"
expect_contains "$assess_txt" "Review/apply: cd proof-patches"
expect_contains "$assess_txt" "Save after proof after rerun:"
expect_contains "$assess_txt" "Evidence sources: .claude/settings.json; .codex/config.toml; .env"
expect_contains "$assess_txt" "Prove at: .ariadne/agent-policy.json; .ariadne/egress-policy.json; .ariadne/output-policy.json; .claude/settings.json; .codex/config.toml"
expect_contains "$assess_txt" "Compare loop:"
expect_contains "$assess_txt" "case-compare.html"

expect_contains "$assess_json" '"run_kind": "assess"'
expect_contains "$assess_json" '"decision"'
expect_contains "$assess_json" '"inspection_summary"'
expect_contains "$assess_json" '"risk_reasons"'
expect_contains "$assess_json" '"evidence_refs"'
expect_contains "$assess_json" '"proof_command"'
expect_contains "$assess_json" '"before_proof_command"'
expect_contains "$assess_json" '"after_proof_command"'
expect_contains "$assess_json" '"present_hard_barriers"'
expect_contains "$assess_json" '"partial_or_friction_controls"'
expect_contains "$assess_json" '"unknown_evidence"'
expect_contains "$assess_json" '"evidence_gap_actions"'
expect_contains "$assess_json" '"done_criteria"'
expect_contains "$assess_json" '"control_state"'
expect_contains "$assess_json" '"current_control": "control:egress-destination-allowlist"'
expect_contains "$assess_json" '"current_proof_surface": ".ariadne/egress-policy.json"'
expect_contains "$assess_json" '"path_summary"'
expect_contains "$assess_json" '"graph_edges"'
expect_contains "$assess_json" 'authority:broad-local|reaches|boundary:external-destination'
expect_contains "$assess_json" '"generated_proof_path": "proof-patches/surfaces/.ariadne/egress-policy.json"'
expect_contains "$assess_json" '"suggested_destination": ".ariadne/egress-policy.json"'
expect_contains "$assess_json" '"destination_path"'
expect_contains "$assess_json" '"apply_command": "cd proof-patches'
expect_contains "$assess_json" '"first_action"'
expect_contains "$assess_json" '"signal_details"'
expect_contains "$assess_json" '"normal_capability"'
expect_contains "$assess_json" '"missing_hard_barrier"'
expect_contains "$assess_json" '"proof_loop"'
expect_contains "$assess_json" '.claude/settings.json'
expect_contains "$assess_json" '.codex/config.toml'

expect_contains "$assess_html" "Ariadne Assessment"
expect_contains "$assess_html" "Decision Packet"
expect_contains "$assess_html" "Inspection Summary"
expect_contains "$assess_html" "Risk Basis"
expect_contains "$assess_html" "Evidence Facts"
expect_contains "$assess_html" "Proof Surface"
expect_contains "$assess_html" "Present Hard Barriers"
expect_contains "$assess_html" "Partial Or Friction Controls"
expect_contains "$assess_html" "Unknown Evidence"
expect_contains "$assess_html" "Evidence Gap Actions"
expect_contains "$assess_html" "Decision Limits"
expect_contains "$assess_html" "Signal Triage"
expect_contains "$assess_html" "Control State"
expect_contains "$assess_html" "State Summary"
expect_contains "$assess_html" "Path To Fix"
expect_contains "$assess_html" "Graph Edges"
expect_contains "$assess_html" "Review / Apply Generated Proof"
expect_contains "$assess_html" "Generated file: proof-patches/surfaces/.ariadne/egress-policy.json"
expect_contains "$assess_html" "Save baseline proof before changes"
expect_contains "$assess_html" "Save after proof after rerun"
expect_contains "$assess_html" "Proof Loop"
expect_contains "$assess_html" "copy-command"
expect_contains "$assess_html" "case-compare.html"

expect_contains "$cases_txt" "Ariadne operator case board:"
expect_contains "$cases_txt" "Evidence sources: .claude/settings.json; .codex/config.toml; .env"
expect_contains "$cases_txt" "Prove at: .ariadne/agent-policy.json; .ariadne/egress-policy.json; .ariadne/output-policy.json; .claude/settings.json; .codex/config.toml"

expect_contains "$proofs_action" "Ariadne Proof Action"
expect_contains "$proofs_action" "Evidence sources:"
expect_contains "$proofs_action" "CLAUDE.md"
expect_contains "$proofs_action" "Proof to add or verify:"
expect_contains "$proofs_action" "Export suggested files:"
expect_contains "$proofs_action" "Compare loop:"

endpoint_action="$workdir/endpoint-assess-action.txt"
endpoint_json="$workdir/endpoint-assess.json"
endpoint_html="$workdir/endpoint-assess.html"
endpoint_cases="$workdir/endpoint-cases.txt"

"$bin" assess --path "$endpoint_fixture" --mode endpoint --format action --out "$endpoint_action"
"$bin" assess --path "$endpoint_fixture" --mode endpoint --format json --out "$endpoint_json"
"$bin" assess --path "$endpoint_fixture" --mode endpoint --format html --out "$endpoint_html"
"$bin" cases --path "$endpoint_fixture" --mode endpoint --case case:least-agency-authority --out "$endpoint_cases"

expect_contains "$endpoint_action" "What was inspected:"
expect_contains "$endpoint_action" "Decision:"
expect_contains "$endpoint_action" "Verdict: action required"
expect_contains "$endpoint_action" "Inspected: AI surfaces:"
expect_contains "$endpoint_action" "Inspected: Runtime surface map:"
expect_contains "$endpoint_action" "Risk basis:"
expect_contains "$endpoint_action" "Evidence fact:"
expect_contains "$endpoint_action" "Before proof:"
expect_contains "$endpoint_action" "--out before-proof.json"
expect_contains "$endpoint_action" "Proof command:"
expect_contains "$endpoint_action" "After proof:"
expect_contains "$endpoint_action" "--out after-proof.json"
expect_contains "$endpoint_action" "Decision limit:"
expect_contains "$endpoint_action" "Decision is derived from deterministic inventory"
expect_contains "$endpoint_action" "Signal triage:"
expect_contains "$endpoint_action" "Normal capability:"
expect_contains "$endpoint_action" "Missing hard barrier:"
expect_contains "$endpoint_action" "Present hard barrier: control:network-restricted"
expect_contains "$endpoint_action" "Control state:"
expect_contains "$endpoint_action" "Current control: control:deny-by-default"
expect_contains "$endpoint_action" "Current proof surface: .ariadne/agent-policy.json"
expect_contains "$endpoint_action" "Missing hard-barrier evidence for control:deny-by-default"
expect_contains "$endpoint_action" "Path to fix:"
expect_contains "$endpoint_action" "Supported graph edge:"
expect_contains "$endpoint_action" "boundary external destination (reaches)"
expect_contains "$endpoint_action" "Save baseline proof before changes:"
expect_contains "$endpoint_action" "Review/apply generated proof file:"
expect_contains "$endpoint_action" "Generated file: proof-patches/surfaces/.ariadne/agent-policy.json"
expect_contains "$endpoint_action" "Review/apply: cd proof-patches"
expect_contains "$endpoint_action" "Save after proof after rerun:"
expect_contains "$endpoint_action" "Least Agency And Authority Scope"
expect_contains "$endpoint_action" "Evidence sources:"
expect_contains "$endpoint_action" ".claude/.mcp.json"
expect_contains "$endpoint_action" ".claude/settings.local.json"
expect_contains "$endpoint_action" ".codex/config.toml"
expect_contains "$endpoint_action" ".continue/config.json"
expect_contains "$endpoint_action" ".cursor/mcp.json"
expect_contains "$endpoint_action" ".gemini/settings.json"
expect_contains "$endpoint_action" "Proof loop:"
expect_contains "$endpoint_action" "case-compare.html"

expect_contains "$endpoint_json" '"mode": "endpoint"'
expect_contains "$endpoint_json" '"decision"'
expect_contains "$endpoint_json" '"inspection_summary"'
expect_contains "$endpoint_json" '"risk_reasons"'
expect_contains "$endpoint_json" '"evidence_refs"'
expect_contains "$endpoint_json" '"proof_command"'
expect_contains "$endpoint_json" '"before_proof_command"'
expect_contains "$endpoint_json" '"after_proof_command"'
expect_contains "$endpoint_json" '"present_hard_barriers"'
expect_contains "$endpoint_json" '"partial_or_friction_controls"'
expect_contains "$endpoint_json" '"unknown_evidence"'
expect_contains "$endpoint_json" '"evidence_gap_actions"'
expect_contains "$endpoint_json" '"done_criteria"'
expect_contains "$endpoint_json" '"top_case_id": "case:least-agency-authority"'
expect_contains "$endpoint_json" '"control_state"'
expect_contains "$endpoint_json" '"current_control": "control:deny-by-default"'
expect_contains "$endpoint_json" '"current_proof_surface": ".ariadne/agent-policy.json"'
expect_contains "$endpoint_json" '"path_summary"'
expect_contains "$endpoint_json" '"graph_edges"'
expect_contains "$endpoint_json" 'authority:broad-local|reaches|boundary:external-destination'
expect_contains "$endpoint_json" '"generated_proof_path": "proof-patches/surfaces/.ariadne/agent-policy.json"'
expect_contains "$endpoint_json" '"suggested_destination": ".ariadne/agent-policy.json"'
expect_contains "$endpoint_json" '"destination_path"'
expect_contains "$endpoint_json" '"apply_command": "cd proof-patches'
expect_contains "$endpoint_json" '"present_hard_barriers"'
expect_contains "$endpoint_json" 'control:network-restricted'
expect_contains "$endpoint_json" '.claude/.mcp.json'
expect_contains "$endpoint_json" '.gemini/settings.json'

expect_contains "$endpoint_html" "Ariadne Assessment"
expect_contains "$endpoint_html" "Decision Packet"
expect_contains "$endpoint_html" "Inspection Summary"
expect_contains "$endpoint_html" "Risk Basis"
expect_contains "$endpoint_html" "Evidence Facts"
expect_contains "$endpoint_html" "Proof Surface"
expect_contains "$endpoint_html" "Present Hard Barriers"
expect_contains "$endpoint_html" "Partial Or Friction Controls"
expect_contains "$endpoint_html" "Unknown Evidence"
expect_contains "$endpoint_html" "Evidence Gap Actions"
expect_contains "$endpoint_html" "Decision Limits"
expect_contains "$endpoint_html" "Signal Triage"
expect_contains "$endpoint_html" "Control State"
expect_contains "$endpoint_html" "State Summary"
expect_contains "$endpoint_html" "Path To Fix"
expect_contains "$endpoint_html" "Graph Edges"
expect_contains "$endpoint_html" "Review / Apply Generated Proof"
expect_contains "$endpoint_html" "Generated file: proof-patches/surfaces/.ariadne/agent-policy.json"
expect_contains "$endpoint_html" "Save baseline proof before changes"
expect_contains "$endpoint_html" "Save after proof after rerun"
expect_contains "$endpoint_html" "Proof Loop"
expect_contains "$endpoint_html" ".claude/.mcp.json"
expect_contains "$endpoint_html" ".gemini/settings.json"
expect_contains "$endpoint_html" "copy-command"

expect_contains "$endpoint_cases" "Case: case:least-agency-authority"
expect_contains "$endpoint_cases" "Evidence sources:"
expect_contains "$endpoint_cases" ".claude/.mcp.json"
expect_contains "$endpoint_cases" ".codex/config.toml"
expect_contains "$endpoint_cases" ".gemini/settings.json"
expect_contains "$endpoint_cases" "Prove at:"

loop_target="$workdir/combined-risk"
cp -R "$fixture" "$loop_target"

before_json="$workdir/before-proof.json"
after_json="$workdir/after-proof.json"
after_case="$workdir/after-case.txt"
compare_txt="$workdir/compare.txt"
compare_json="$workdir/compare.json"
compare_html="$workdir/compare.html"
export_dir="$workdir/proof-patches"
export_log="$workdir/proof-export.log"

"$bin" proofs --path "$loop_target" --case case:input-trust-boundary --format json --out "$before_json"
"$bin" proofs --path "$loop_target" --case case:input-trust-boundary --patch-dir "$export_dir" --format action --out "$workdir/proof-export-action.txt" 2> "$export_log"

expect_contains "$export_log" "Generated proof files:"
expect_contains "$export_log" "Review/apply:"
expect_contains "$export_log" "input-policy.json"

mkdir -p "$loop_target/.ariadne"
cp "$export_dir/surfaces/.ariadne/input-policy.json" "$loop_target/.ariadne/input-policy.json"

"$bin" cases --path "$loop_target" --case case:input-trust-boundary --out "$after_case"
"$bin" proofs --path "$loop_target" --case case:input-trust-boundary --format json --out "$after_json"
"$bin" compare --before "$before_json" --after "$after_json" --out "$compare_txt"
"$bin" compare --before "$before_json" --after "$after_json" --format json --out "$compare_json"
"$bin" compare --before "$before_json" --after "$after_json" --format html --out "$compare_html"

expect_contains "$after_case" "State: closed"
expect_contains "$after_case" "0 missing hard-barrier controls"
expect_contains "$after_case" ".ariadne/input-policy.json"

expect_contains "$compare_txt" "open -> closed"
expect_contains "$compare_txt" "Proof patches: 2 -> 0"
expect_contains "$compare_txt" "Added evidence:"
expect_contains "$compare_txt" ".ariadne/input-policy.json"

expect_contains "$compare_json" '"before_state": "open"'
expect_contains "$compare_json" '"after_state": "closed"'
expect_contains "$compare_json" '"added_evidence_refs"'
expect_contains "$compare_html" "CLOSED"
expect_contains "$compare_html" "open"
expect_contains "$compare_html" "closed"
expect_contains "$compare_html" ".ariadne/input-policy.json"

echo "First-run verification passed"
echo "  artifacts: $workdir"
